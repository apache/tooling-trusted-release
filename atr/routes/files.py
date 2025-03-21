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

"""package.py"""

from __future__ import annotations

import os
import pathlib
import re
from typing import TYPE_CHECKING, Any, Final, NoReturn, Protocol, TypeVar

import asfquart.auth as auth
import asfquart.base as base
import asfquart.session as session
import quart

import atr.analysis as analysis
import atr.config as config
import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.user as user
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

R = TypeVar("R", covariant=True)

_CONFIG: Final = config.get()


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
    async def user_editable_releases(self) -> list[Any]:
        return await user.editable_releases(self.uid, user_projects=self._projects)

    @property
    async def user_projects(self) -> list[Any]:
        if self._projects is None:
            self._projects = await user.projects(self.uid)
        return self._projects

    @property
    async def user_releases(self) -> list[Any]:
        return await user.releases(self.uid)


# This is the type of functions to which we apply @app_route
# In other words, functions which accept no session
class RouteHandler(Protocol[R]):
    """Protocol for @app_route decorated functions."""

    __name__: str
    __doc__: str | None

    def __call__(self, *args: Any, **kwargs: Any) -> Awaitable[R]: ...


def _authentication_failed() -> NoReturn:
    """Handle authentication failure with an exception."""
    # NOTE: This is a separate function to fix a problem with analysis flow in mypy
    raise base.ASFQuartException("Not authenticated", errorcode=401)


async def _number_of_release_files(release: models.Release) -> int:
    """Return the number of files in the release."""
    path_project = release.project.name
    path_version = release.version
    path = os.path.join(_CONFIG.STATE_DIR, "rsync-files", path_project, path_version)
    return len(await util.paths_recursive(path))


def _path_warnings_errors(
    paths: set[str], path: str, ext_artifact: str | None, ext_metadata: str | None
) -> tuple[list[str], list[str]]:
    # NOTE: This is important institutional logic
    # TODO: We should probably move this to somewhere more important than a routes module
    warnings = []
    errors = []
    filename = os.path.basename(path)

    # The Release Distribution Policy specifically allows README and CHANGES, etc.
    # We assume that LICENSE and NOTICE are permitted also
    if filename == "KEYS":
        errors.append("Please upload KEYS to ATR directly instead of using rsync")
    elif path.startswith(".") or ("/." in path):
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


def _path_warnings_errors_artifact(paths: set[str], path: str, ext_artifact: str) -> tuple[list[str], list[str]]:
    # We refer to the following authoritative policies:
    # - Release Creation Process (RCP)
    # - Release Distribution Policy (RDP)

    warnings: list[str] = []
    errors: list[str] = []

    # RDP says that .asc is required and one of .sha256 or .sha512
    if (path + ".asc") not in paths:
        errors.append("Missing an .asc counterpart")
    no_sha256 = (path + ".sha256") not in paths
    no_sha512 = (path + ".sha512") not in paths
    if no_sha256 and no_sha512:
        errors.append("Missing a .sha256 or .sha512 counterpart")

    return warnings, errors


def _path_warnings_errors_metadata(paths: set[str], path: str, ext_metadata: str) -> tuple[list[str], list[str]]:
    # We refer to the following authoritative policies:
    # - Release Creation Process (RCP)
    # - Release Distribution Policy (RDP)

    warnings: list[str] = []
    errors: list[str] = []
    suffixes = set(pathlib.Path(path).suffixes)

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
    artifact_path = path.removesuffix(ext_metadata)
    if artifact_path not in paths:
        errors.append("Missing an artifact counterpart")

    return warnings, errors


# This decorator is an adaptor between @committer_get and @app_route functions
def committer_get(path: str) -> Callable[[CommitterRouteHandler[R]], RouteHandler[R]]:
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
        decorated = routes.app_route(path, methods=["GET"])(decorated)

        return decorated

    return decorator


@committer_get("/files/add")
async def root_files_add(session: CommitterSession) -> str:
    """Show a page to allow the user to rsync files to editable releases."""
    # Do them outside of the template rendering call to ensure order
    # The user_editable_releases call can use cached results from user_projects
    user_projects = await session.user_projects
    user_editable_releases = await session.user_editable_releases

    return await quart.render_template(
        "files-add.html",
        asf_id=session.uid,
        projects=user_projects,
        server_domain=session.host,
        number_of_release_files=_number_of_release_files,
        editable_releases=user_editable_releases,
    )


@committer_get("/files/list/<project_name>/<version_name>")
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

    base_path = os.path.join(_CONFIG.STATE_DIR, "rsync-files", project_name, version_name)
    paths = await util.paths_recursive(base_path)
    paths_set = set(paths)
    path_templates = {}
    path_substitutions = {}
    path_artifacts = set()
    path_metadata = set()
    path_warnings = {}
    path_errors = {}
    for path in paths:
        # Get template and substitutions
        elements = {
            "core": project_name,
            "version": version_name,
            "sub": None,
            "template": None,
            "substitutions": None,
        }
        template, substitutions = analysis.filename_parse(path, elements)
        path_templates[path] = template
        path_substitutions[path] = analysis.substitutions_format(substitutions) or "none"

        # Get artifacts and metadata
        search = re.search(analysis.extension_pattern(), path)
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
    )
