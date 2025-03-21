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
from typing import TYPE_CHECKING, Any, Final, NoReturn, Protocol, TypeVar

import aiofiles.os
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
    return len(await _paths_recursive_list(path))


async def _paths_recursive_list(base_path: str) -> list[str]:
    """List all paths recursively in alphabetical order from a given base path."""
    paths: list[str] = []

    async def _recursive_list(current_path: str, relative_path: str = "") -> None:
        try:
            entries = await aiofiles.os.listdir(current_path)
            for entry in entries:
                entry_path = os.path.join(current_path, entry)
                entry_rel_path = os.path.join(relative_path, entry) if relative_path else entry

                try:
                    stat_info = await aiofiles.os.stat(entry_path)
                    # If the entry is a directory, recurse into it
                    if stat_info.st_mode & 0o040000:
                        await _recursive_list(entry_path, entry_rel_path)
                    else:
                        paths.append(entry_rel_path)
                except (FileNotFoundError, PermissionError):
                    continue
        except FileNotFoundError:
            pass

    await _recursive_list(base_path)
    paths.sort()
    return paths


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
    paths = await _paths_recursive_list(base_path)
    path_templates = {}
    path_substitutions = {}
    for path in paths:
        elements = {
            "core": project_name,
            "version": version_name,
            "sub": None,
            "template": None,
            "substitutions": None,
        }
        template, substitutions = analysis.filename_parse(path, elements)
        path_templates[path] = template
        subs = []
        for key, values in substitutions.items():
            if values:
                subs.append(f"{key.upper()}: {', '.join(values)}")
        if subs:
            path_substitutions[path] = ", ".join(subs)
        else:
            path_substitutions[path] = "none"

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
    )
