# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""files.py"""

from __future__ import annotations

import asyncio
import datetime
import logging
import pathlib
import re
from typing import TYPE_CHECKING, Any, Final, NoReturn, Protocol, TypeVar

import aiofiles.os
import asfquart.auth as auth
import asfquart.base as base
import asfquart.session as session
import quart
import werkzeug.datastructures as datastructures
import werkzeug.wrappers.response as response
import wtforms

import atr.analysis as analysis
import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.user as user
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

R = TypeVar("R", covariant=True)

# _CONFIG: Final = config.get()
_LOGGER: Final = logging.getLogger(__name__)


# This is the type of functions to which we apply @committer_get
# In other words, functions which accept CommitterSession as their first arg
class CommitterRouteHandler(Protocol[R]):
    """Protocol for @committer_get decorated functions."""

    __name__: str
    __doc__: str | None

    def __call__(self, session: CommitterSession, *args: Any, **kwargs: Any) -> Awaitable[R]: ...


class CommitterSession:
    """Session with extra information about committers."""

    def __init__(self, web_session: session.ClientSession) -> None:
        self._projects: list[models.Project] | None = None
        self._session = web_session

    def __getattr__(self, name: str) -> Any:
        # TODO: Not type safe, should subclass properly if possible
        # For example, we can access session.no_such_attr and the type checkers won't notice
        return getattr(self._session, name)

    @property
    def host(self) -> str:
        request_host = quart.request.host
        if ":" in request_host:
            domain, port = request_host.split(":")
            # Could be an IPv6 address, so need to check whether port is a valid integer
            if port.isdigit():
                return domain
        return request_host

    @property
    async def user_candidate_drafts(self) -> list[models.Release]:
        return await user.candidate_drafts(self.uid, user_projects=self._projects)

    @property
    async def user_projects(self) -> list[models.Project]:
        if self._projects is None:
            self._projects = await user.projects(self.uid)
        return self._projects

    @property
    async def user_releases(self) -> list[models.Release]:
        return await user.releases(self.uid)


# This is the type of functions to which we apply @app_route
# In other words, functions which accept no session
class RouteHandler(Protocol[R]):
    """Protocol for @app_route decorated functions."""

    __name__: str
    __doc__: str | None

    def __call__(self, *args: Any, **kwargs: Any) -> Awaitable[R]: ...


class FilesAddOneForm(util.QuartFormTyped):
    """Form for adding a single file to a release candidate."""

    file_path = wtforms.StringField("File path (optional)", validators=[wtforms.validators.Optional()])
    file_data = wtforms.FileField("File", validators=[wtforms.validators.InputRequired("File is required")])
    submit = wtforms.SubmitField("Add file")


def _authentication_failed() -> NoReturn:
    """Handle authentication failure with an exception."""
    # NOTE: This is a separate function to fix a problem with analysis flow in mypy
    raise base.ASFQuartException("Not authenticated", errorcode=401)


async def _get_recent_tasks_by_type(
    data: db.Session, release_name: str, file_path: str, modified: int
) -> dict[str, models.Task]:
    """Get the most recent task for each task type for a specific file."""
    tasks = await data.task(
        release_name=release_name,
        path=str(file_path),
        modified=modified,
    ).all()

    # Group by task_type and keep the most recent one
    # We use the highest id to determine the most recent task
    recent_tasks: dict[str, models.Task] = {}
    for task in tasks:
        # If we haven't seen this task type before or if this task is newer
        if (task.task_type not in recent_tasks) or (task.id > recent_tasks[task.task_type].id):
            recent_tasks[task.task_type] = task

    return recent_tasks


async def _number_of_release_files(release: models.Release) -> int:
    """Return the number of files in the release."""
    path_project = release.project.name
    path_version = release.version
    path = util.get_candidate_draft_dir() / path_project / path_version
    return len(await util.paths_recursive(path))


def _path_warnings_errors(
    paths: set[pathlib.Path], path: pathlib.Path, ext_artifact: str | None, ext_metadata: str | None
) -> tuple[list[str], list[str]]:
    # NOTE: This is important institutional logic
    # TODO: We should probably move this to somewhere more important than a routes module
    warnings = []
    errors = []

    # The Release Distribution Policy specifically allows README and CHANGES, etc.
    # We assume that LICENSE and NOTICE are permitted also
    if path.name == "KEYS":
        errors.append("Please upload KEYS to ATR directly instead of using rsync")
    elif any(part.startswith(".") for part in path.parts):
        # TODO: There is not a a policy for this
        # We should enquire as to whether such a policy should be instituted
        # We're forbidding dotfiles to catch accidental uploads of e.g. .git or .htaccess
        # Such cases are likely to be in error, and could carry security risks
        errors.append("Dotfiles are forbidden")

    if ext_artifact:
        updated_warnings, updated_errors = _path_warnings_errors_artifact(paths, path, ext_artifact)
        warnings.extend(updated_warnings)
        errors.extend(updated_errors)

    if ext_metadata:
        updated_warnings, updated_errors = _path_warnings_errors_metadata(paths, path, ext_metadata)
        warnings.extend(updated_warnings)
        errors.extend(updated_errors)

    return warnings, errors


def _path_warnings_errors_artifact(
    paths: set[pathlib.Path], path: pathlib.Path, ext_artifact: str
) -> tuple[list[str], list[str]]:
    # We refer to the following authoritative policies:
    # - Release Creation Process (RCP)
    # - Release Distribution Policy (RDP)

    warnings: list[str] = []
    errors: list[str] = []

    # RDP says that .asc is required and one of .sha256 or .sha512
    if path.with_suffix(path.suffix + ".asc") not in paths:
        errors.append("Missing an .asc counterpart")
    no_sha256 = path.with_suffix(path.suffix + ".sha256") not in paths
    no_sha512 = path.with_suffix(path.suffix + ".sha512") not in paths
    if no_sha256 and no_sha512:
        errors.append("Missing a .sha256 or .sha512 counterpart")

    return warnings, errors


def _path_warnings_errors_metadata(
    paths: set[pathlib.Path], path: pathlib.Path, ext_metadata: str
) -> tuple[list[str], list[str]]:
    # We refer to the following authoritative policies:
    # - Release Creation Process (RCP)
    # - Release Distribution Policy (RDP)

    warnings: list[str] = []
    errors: list[str] = []
    suffixes = set(path.suffixes)

    if ".md5" in suffixes:
        # Forbidden by RCP, deprecated by RDP
        errors.append("The use of .md5 is forbidden, please use .sha512")
    if ".sha1" in suffixes:
        # Deprecated by RDP
        warnings.append("The use of .sha1 is deprecated, please use .sha512")
    if ".sha" in suffixes:
        # Discouraged by RDP
        warnings.append("The use of .sha is discouraged, please use .sha512")
    if ".sig" in suffixes:
        # Forbidden by RCP, forbidden by RDP
        errors.append("Binary signature files are forbidden, please use .asc")

    # "Signature and checksum files for verifying distributed artifacts should
    # not be provided, unless named as indicated above." (RDP)
    # Also .mds is allowed, but we'll ignore that for now
    # TODO: Is .mds supported in analysis.METADATA_SUFFIXES?
    if ext_metadata not in {".asc", ".sha256", ".sha512", ".md5", ".sha", ".sha1"}:
        warnings.append("The use of this metadata file is discouraged")

    # If a metadata file is present, it must have an artifact counterpart
    artifact_path = path.with_name(path.name.removesuffix(ext_metadata))
    if artifact_path not in paths:
        errors.append("Missing an artifact counterpart")

    return warnings, errors


# This decorator is an adaptor between @committer_get and @app_route functions
def committer_route(
    path: str, methods: list[str] | None = None
) -> Callable[[CommitterRouteHandler[R]], RouteHandler[R]]:
    """Decorator for committer GET routes that provides an enhanced session object."""

    def decorator(func: CommitterRouteHandler[R]) -> RouteHandler[R]:
        async def wrapper(*args: Any, **kwargs: Any) -> R:
            web_session = await session.read()
            if web_session is None:
                _authentication_failed()

            enhanced_session = CommitterSession(web_session)
            return await func(enhanced_session, *args, **kwargs)

        # Set the name before applying decorators
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__

        # Apply decorators in reverse order
        decorated = auth.require(auth.Requirements.committer)(wrapper)
        decorated = routes.app_route(path, methods=methods or ["GET"])(decorated)

        return decorated

    return decorator


@committer_route("/files/add")
async def root_files_add(session: CommitterSession) -> str:
    """Show a page to allow the user to rsync files to candidate drafts."""
    # Do them outside of the template rendering call to ensure order
    # The user_candidate_drafts call can use cached results from user_projects
    user_projects = await session.user_projects
    user_candidate_drafts = await session.user_candidate_drafts

    return await quart.render_template(
        "files-add.html",
        asf_id=session.uid,
        projects=user_projects,
        server_domain=session.host,
        number_of_release_files=_number_of_release_files,
        candidate_drafts=user_candidate_drafts,
    )


async def _add_one(
    project_name: str,
    version_name: str,
    file_path: pathlib.Path | None,
    file: datastructures.FileStorage,
) -> None:
    """Process and save the uploaded file."""
    # Create target directory
    target_dir = util.get_candidate_draft_dir() / project_name / version_name
    target_dir.mkdir(parents=True, exist_ok=True)

    # Use the original filename if no path is specified
    if not file_path:
        if not file.filename:
            raise routes.FlashError("No filename provided")
        file_path = pathlib.Path(file.filename)

    # Save file to specified path
    target_path = target_dir / file_path.relative_to(file_path.anchor)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    async with aiofiles.open(target_path, "wb") as f:
        while True:
            chunk = await asyncio.to_thread(file.stream.read, 8192)
            if not chunk:
                break
            await f.write(chunk)


@committer_route("/files/add/<project_name>/<version_name>", methods=["GET", "POST"])
async def root_files_add_project(
    session: CommitterSession, project_name: str, version_name: str
) -> response.Response | str:
    """Show a page to allow the user to add a single file to a candidate draft."""
    form = await FilesAddOneForm.create_form()
    if await form.validate_on_submit():
        try:
            file_path = None
            if isinstance(form.file_path.data, str):
                file_path = pathlib.Path(form.file_path.data)
            file_data = form.file_data.data
            if not isinstance(file_data, datastructures.FileStorage):
                raise routes.FlashError("Invalid file upload")

            await _add_one(project_name, version_name, file_path, file_data)
            await quart.flash("File added successfully", "success")
            return quart.redirect(
                quart.url_for("root_files_list", project_name=project_name, version_name=version_name)
            )
        except Exception as e:
            logging.exception("Error adding file:")
            await quart.flash(f"Error adding file: {e!s}", "error")

    return await quart.render_template(
        "files-add-project.html",
        asf_id=session.uid,
        server_domain=session.host,
        project_name=project_name,
        version_name=version_name,
        form=form,
    )


@committer_route("/files/list/<project_name>/<version_name>")
async def root_files_list(session: CommitterSession, project_name: str, version_name: str) -> str:
    """Show all the files in the rsync upload directory for a release."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    # Check that the release exists
    async with db.session() as data:
        release = await data.release(name=f"{project_name}-{version_name}", _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

    base_path = util.get_candidate_draft_dir() / project_name / version_name
    paths = await util.paths_recursive(base_path)
    paths_set = set(paths)
    path_templates = {}
    path_substitutions = {}
    path_artifacts = set()
    path_metadata = set()
    path_warnings = {}
    path_errors = {}
    path_modified = {}
    path_tasks: dict[pathlib.Path, dict[str, models.Task]] = {}
    for path in paths:
        # Get template and substitutions
        elements = {
            "core": project_name,
            "version": version_name,
            "sub": None,
            "template": None,
            "substitutions": None,
        }
        template, substitutions = analysis.filename_parse(str(path), elements)
        path_templates[path] = template
        path_substitutions[path] = analysis.substitutions_format(substitutions) or "none"

        # Get artifacts and metadata
        search = re.search(analysis.extension_pattern(), str(path))
        ext_artifact = None
        ext_metadata = None
        if search:
            ext_artifact = search.group("artifact")
            # ext_metadata_artifact = search.group("metadata_artifact")
            ext_metadata = search.group("metadata")
            if ext_artifact:
                path_artifacts.add(path)
            elif ext_metadata:
                path_metadata.add(path)

        # Get warnings and errors
        path_warnings[path], path_errors[path] = _path_warnings_errors(paths_set, path, ext_artifact, ext_metadata)

        # Get modified time
        full_path = str(util.get_candidate_draft_dir() / project_name / version_name / path)
        path_modified[path] = int(await aiofiles.os.path.getmtime(full_path))

        # Get the most recent task for each type
        path_tasks[path] = await _get_recent_tasks_by_type(
            data, f"{project_name}-{version_name}", str(path), path_modified[path]
        )

    return await quart.render_template(
        "files-list.html",
        asf_id=session.uid,
        project_name=project_name,
        version_name=version_name,
        release=release,
        paths=paths,
        server_domain=session.host,
        templates=path_templates,
        substitutions=path_substitutions,
        artifacts=path_artifacts,
        metadata=path_metadata,
        warnings=path_warnings,
        errors=path_errors,
        modified=path_modified,
        tasks=path_tasks,
        models=models,
    )


@committer_route("/files/checks/<project_name>/<version_name>/<path:file_path>")
async def root_files_checks(session: CommitterSession, project_name: str, version_name: str, file_path: str) -> str:
    """Show the status of all checks for a specific file."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        # Check that the release exists
        release = await data.release(name=f"{project_name}-{version_name}", _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

        full_path = str(util.get_candidate_draft_dir() / project_name / version_name / file_path)

        # Check that the file exists
        if not await aiofiles.os.path.exists(full_path):
            raise base.ASFQuartException("File does not exist", errorcode=404)

        modified = int(await aiofiles.os.path.getmtime(full_path))
        file_size = await aiofiles.os.path.getsize(full_path)

        # Get the most recent task for each task type
        recent_tasks = await _get_recent_tasks_by_type(data, f"{project_name}-{version_name}", file_path, modified)

        # Convert to a list for the template
        tasks = list(recent_tasks.values())

        all_tasks_completed = all(
            task.status in (models.TaskStatus.COMPLETED, models.TaskStatus.FAILED) for task in tasks
        )

    file_data = {
        "filename": pathlib.Path(file_path).name,
        "bytes_size": file_size,
        "uploaded": datetime.datetime.fromtimestamp(modified, tz=datetime.UTC),
    }

    return await quart.render_template(
        "files-check.html",
        project_name=project_name,
        version_name=version_name,
        file_path=file_path,
        package=file_data,
        release=release,
        tasks=tasks,
        all_tasks_completed=all_tasks_completed,
        format_file_size=routes.format_file_size,
    )
