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

from typing import TYPE_CHECKING, Any, NoReturn, Protocol, TypeVar

import asfquart.auth as auth
import asfquart.base as base
import asfquart.session as session
import quart

import atr.db as db
import atr.db.models as models
import atr.routes as routes

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

R = TypeVar("R", covariant=True)


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
    async def user_projects(self) -> list[Any]:
        user_projects: list[models.Project] = []
        async with db.session() as data:
            projects = await data.project(_committee=True, _releases=True).all()
            for p in projects:
                if p.committee is None:
                    continue
                if (self.uid in p.committee.committee_members) or (self.uid in p.committee.committers):
                    user_projects.append(p)

        return user_projects

    @property
    async def user_releases(self) -> list[Any]:
        user_releases: list[models.Release] = []
        async with db.session() as data:
            # TODO: We're limiting this to candidates
            # We should either call this user_candidate_releases, or change the query
            releases = await data.release(stage=models.ReleaseStage.CANDIDATE, _project=True, _committee=True).all()
            user_releases = []
            for r in releases:
                if r.committee is None:
                    continue
                if (self.uid in r.committee.committee_members) or (self.uid in r.committee.committers):
                    user_releases.append(r)

        return user_releases


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


def number_of_release_files(release: models.Release) -> int:
    """Return the number of files in the release."""
    # TODO: Return the number of files in the release
    return 0


@committer_get("/files/add")
async def root_files_add(session: CommitterSession) -> str:
    """Show a page to allow the user to rsync files to editable releases."""
    return await quart.render_template(
        "files-add.html",
        asf_id=session.uid,
        projects=await session.user_projects,
        server_domain=session.host,
        number_of_release_files=number_of_release_files,
    )
