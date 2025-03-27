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

"""candidate_draft.py"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import logging
import pathlib
import re
import sys
from typing import Final

import aiofiles.os
import asfquart.base as base
import quart
import werkzeug.datastructures as datastructures
import werkzeug.wrappers.response as response
import wtforms

import atr.analysis as analysis
import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.tasks as tasks
import atr.util as util

# _CONFIG: Final = config.get()
_LOGGER: Final = logging.getLogger(__name__)


class FilesAddOneForm(util.QuartFormTyped):
    """Form for adding a single file to a release candidate."""

    file_path = wtforms.StringField("File path (optional)", validators=[wtforms.validators.Optional()])
    file_data = wtforms.FileField("File", validators=[wtforms.validators.InputRequired("File is required")])
    submit = wtforms.SubmitField("Add file")


async def _number_of_release_files(release: models.Release) -> int:
    """Return the number of files in the release."""
    path_project = release.project.name
    path_version = release.version
    path = util.get_release_candidate_draft_dir() / path_project / path_version
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


@routes.committer("/candidate/draft/add")
async def add(session: routes.CommitterSession) -> str:
    """Show a page to allow the user to rsync files to candidate drafts."""
    # Do them outside of the template rendering call to ensure order
    # The user_candidate_drafts call can use cached results from user_projects
    user_projects = await session.user_projects
    user_candidate_drafts = await session.user_candidate_drafts

    return await quart.render_template(
        "candidate-draft-add.html",
        asf_id=session.uid,
        projects=user_projects,
        server_domain=session.host,
        number_of_release_files=_number_of_release_files,
        candidate_drafts=user_candidate_drafts,
        candidate_draft=sys.modules[__name__],
    )


async def _add_one(
    project_name: str,
    version_name: str,
    file_path: pathlib.Path | None,
    file: datastructures.FileStorage,
) -> None:
    """Process and save the uploaded file."""
    # Create target directory
    target_dir = util.get_release_candidate_draft_dir() / project_name / version_name
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


@routes.committer("/candidate/draft/add/<project_name>/<version_name>", methods=["GET", "POST"])
async def add_project(
    session: routes.CommitterSession, project_name: str, version_name: str
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
            return quart.redirect(util.as_url(files, project_name=project_name, version_name=version_name))
        except Exception as e:
            logging.exception("Error adding file:")
            await quart.flash(f"Error adding file: {e!s}", "error")

    return await quart.render_template(
        "candidate-draft-add-project.html",
        asf_id=session.uid,
        server_domain=session.host,
        project_name=project_name,
        version_name=version_name,
        form=form,
        candidate_draft=sys.modules[__name__],
    )


@routes.committer("/candidate/draft/files/<project_name>/<version_name>")
async def files(session: routes.CommitterSession, project_name: str, version_name: str) -> str:
    """Show all the files in the rsync upload directory for a release."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    # Check that the release exists
    async with db.session() as data:
        release = await data.release(name=f"{project_name}-{version_name}", _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

    base_path = util.get_release_candidate_draft_dir() / project_name / version_name
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
        full_path = str(util.get_release_candidate_draft_dir() / project_name / version_name / path)
        path_modified[path] = int(await aiofiles.os.path.getmtime(full_path))

        # Get the most recent task for each type
        path_tasks[path] = await db.recent_tasks(data, f"{project_name}-{version_name}", str(path), path_modified[path])

    return await quart.render_template(
        "candidate-draft-list.html",
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
        candidate_draft=sys.modules[__name__],
    )


@routes.committer("/candidate/draft/checks/<project_name>/<version_name>/<path:file_path>")
async def checks(session: routes.CommitterSession, project_name: str, version_name: str, file_path: str) -> str:
    """Show the status of all checks for a specific file."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        # Check that the release exists
        release = await data.release(name=f"{project_name}-{version_name}", _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

        full_path = str(util.get_release_candidate_draft_dir() / project_name / version_name / file_path)

        # Check that the file exists
        if not await aiofiles.os.path.exists(full_path):
            raise base.ASFQuartException("File does not exist", errorcode=404)

        modified = int(await aiofiles.os.path.getmtime(full_path))
        file_size = await aiofiles.os.path.getsize(full_path)

        # Get the most recent task for each task type
        recent_tasks = await db.recent_tasks(data, f"{project_name}-{version_name}", file_path, modified)

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
        "candidate-draft-check.html",
        project_name=project_name,
        version_name=version_name,
        file_path=file_path,
        package=file_data,
        release=release,
        tasks=tasks,
        all_tasks_completed=all_tasks_completed,
        format_file_size=routes.format_file_size,
        candidate_draft=sys.modules[__name__],
    )


@routes.committer("/candidate/draft/delete/<project_name>/<version_name>/<path:file_path>", methods=["POST"])
async def delete(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response:
    """Delete a specific file from the release candidate."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        # Check that the release exists
        await data.release(name=f"{project_name}-{version_name}", _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

        full_path = str(util.get_release_candidate_draft_dir() / project_name / version_name / file_path)

        # Check that the file exists
        if not await aiofiles.os.path.exists(full_path):
            raise base.ASFQuartException("File does not exist", errorcode=404)

        # Delete the file
        await aiofiles.os.remove(full_path)

    await quart.flash("File deleted successfully", "success")
    return quart.redirect(util.as_url(files, project_name=project_name, version_name=version_name))


@routes.committer("/candidate/draft/hashgen/<project_name>/<version_name>/<path:file_path>", methods=["POST"])
async def hashgen(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response:
    """Generate an sha256 or sha512 hash file for a candidate draft file."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        # Check that the release exists
        release = await data.release(name=f"{project_name}-{version_name}", _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

        # Get the hash type from the form data
        # This is just a button, so we don't make a whole form validation schema for it
        form = await quart.request.form
        hash_type = form.get("hash_type")
        if hash_type not in {"sha256", "sha512"}:
            raise base.ASFQuartException("Invalid hash type", errorcode=400)

        # Construct paths
        base_path = util.get_release_candidate_draft_dir() / project_name / version_name
        full_path = base_path / file_path
        hash_path = file_path + f".{hash_type}"
        full_hash_path = base_path / hash_path

        # Check that the source file exists
        if not await aiofiles.os.path.exists(full_path):
            raise base.ASFQuartException("Source file does not exist", errorcode=404)

        # Check that the hash file does not already exist
        if await aiofiles.os.path.exists(full_hash_path):
            raise base.ASFQuartException(f"{hash_type} file already exists", errorcode=400)

        # Read the file and compute the hash
        hash_obj = hashlib.sha256() if hash_type == "sha256" else hashlib.sha512()
        async with aiofiles.open(full_path, "rb") as f:
            while chunk := await f.read(8192):
                hash_obj.update(chunk)

        # Write the hash file
        hash_value = hash_obj.hexdigest()
        async with aiofiles.open(full_hash_path, "w") as f:
            await f.write(f"{hash_value}  {file_path}\n")

        # Add any relevant tasks to the database
        for task in await tasks.sha_checks(release, str(hash_path)):
            data.add(task)
        await data.commit()

    await quart.flash(f"{hash_type} file generated successfully", "success")
    return quart.redirect(util.as_url(files, project_name=project_name, version_name=version_name))


@routes.committer("/candidate/draft/tools/<project_name>/<version_name>/<path:file_path>")
async def tools(session: routes.CommitterSession, project_name: str, version_name: str, file_path: str) -> str:
    """Show the tools for a specific file."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        # Check that the release exists
        release = await data.release(name=f"{project_name}-{version_name}", _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

        full_path = str(util.get_release_candidate_draft_dir() / project_name / version_name / file_path)

        # Check that the file exists
        if not await aiofiles.os.path.exists(full_path):
            raise base.ASFQuartException("File does not exist", errorcode=404)

        modified = int(await aiofiles.os.path.getmtime(full_path))
        file_size = await aiofiles.os.path.getsize(full_path)

    file_data = {
        "filename": pathlib.Path(file_path).name,
        "bytes_size": file_size,
        "uploaded": datetime.datetime.fromtimestamp(modified, tz=datetime.UTC),
    }

    return await quart.render_template(
        "candidate-draft-tools.html",
        asf_id=session.uid,
        project_name=project_name,
        version_name=version_name,
        file_path=file_path,
        file_data=file_data,
        release=release,
        format_file_size=routes.format_file_size,
        candidate_draft=sys.modules[__name__],
    )
