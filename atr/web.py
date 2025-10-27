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

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, TypeVar

import asfquart.base as base
import asfquart.session as session
import quart

import atr.config as config
import atr.db as db
import atr.models.sql as sql
import atr.user as user
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import Awaitable, Sequence

    import werkzeug.wrappers.response as response


R = TypeVar("R", covariant=True)


class CommitterRouteFunction(Protocol[R]):
    """Protocol for @committer_get decorated functions."""

    __name__: str
    __doc__: str | None

    def __call__(self, session: Committer, *args: Any, **kwargs: Any) -> Awaitable[R]: ...


class Committer:
    """Session with extra information about committers."""

    def __init__(self, web_session: session.ClientSession) -> None:
        self._projects: list[sql.Project] | None = None
        self._session = web_session

    @property
    def asf_uid(self) -> str:
        if self._session.uid is None:
            raise base.ASFQuartException("Not authenticated", errorcode=401)
        return self._session.uid

    def __getattr__(self, name: str) -> Any:
        # TODO: Not type safe, should subclass properly if possible
        # For example, we can access session.no_such_attr and the type checkers won't notice
        return getattr(self._session, name)

    async def check_access(self, project_name: str) -> None:
        if not any((p.name == project_name) for p in (await self.user_projects)):
            if user.is_admin(self.uid):
                # Admins can view all projects
                # But we must warn them when the project is not one of their own
                # TODO: This code is difficult to test locally
                # TODO: This flash sometimes displays after deleting a project, which is a bug
                await quart.flash("This is not your project, but you have access as an admin", "warning")
                return
            raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async def check_access_committee(self, committee_name: str) -> None:
        if committee_name not in self.committees:
            if user.is_admin(self.uid):
                # Admins can view all committees
                # But we must warn them when the committee is not one of their own
                # TODO: As above, this code is difficult to test locally
                await quart.flash("This is not your committee, but you have access as an admin", "warning")
                return
            raise base.ASFQuartException("You do not have access to this committee", errorcode=403)

    @property
    def app_host(self) -> str:
        return config.get().APP_HOST

    @property
    def host(self) -> str:
        request_host = quart.request.host
        if ":" in request_host:
            domain, port = request_host.split(":")
            # Could be an IPv6 address, so need to check whether port is a valid integer
            if port.isdigit():
                return domain
        return request_host

    def only_user_releases(self, releases: Sequence[sql.Release]) -> list[sql.Release]:
        return util.user_releases(self.uid, releases)

    async def redirect(
        self, route: CommitterRouteFunction[R], success: str | None = None, error: str | None = None, **kwargs: Any
    ) -> response.Response:
        """Redirect to a route with a success or error message."""
        return await redirect(route, success, error, **kwargs)

    async def release(
        self,
        project_name: str,
        version_name: str,
        phase: sql.ReleasePhase | db.NotSet | None = db.NOT_SET,
        latest_revision_number: str | db.NotSet | None = db.NOT_SET,
        data: db.Session | None = None,
        with_committee: bool = True,
        with_project: bool = True,
        with_release_policy: bool = False,
        with_project_release_policy: bool = False,
        with_revisions: bool = False,
    ) -> sql.Release:
        # We reuse db.NOT_SET as an entirely different sentinel
        # TODO: We probably shouldn't do that, or should make it clearer
        if phase is None:
            phase_value = db.NOT_SET
        elif phase is db.NOT_SET:
            phase_value = sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
        else:
            phase_value = phase
        release_name = sql.release_name(project_name, version_name)
        if data is None:
            async with db.session() as data:
                release = await data.release(
                    name=release_name,
                    phase=phase_value,
                    latest_revision_number=latest_revision_number,
                    _committee=with_committee,
                    _project=with_project,
                    _release_policy=with_release_policy,
                    _project_release_policy=with_project_release_policy,
                    _revisions=with_revisions,
                ).demand(base.ASFQuartException("Release does not exist", errorcode=404))
        else:
            release = await data.release(
                name=release_name,
                phase=phase_value,
                latest_revision_number=latest_revision_number,
                _committee=with_committee,
                _project=with_project,
                _release_policy=with_release_policy,
                _project_release_policy=with_project_release_policy,
                _revisions=with_revisions,
            ).demand(base.ASFQuartException("Release does not exist", errorcode=404))
        return release

    @property
    async def user_candidate_drafts(self) -> list[sql.Release]:
        return await user.candidate_drafts(self.uid, user_projects=self._projects)

    # @property
    # async def user_committees(self) -> list[models.Committee]:
    #     return ...

    @property
    async def user_projects(self) -> list[sql.Project]:
        if self._projects is None:
            self._projects = await user.projects(self.uid)
        return self._projects[:]


class RouteFunction(Protocol[R]):
    """Protocol for @app_route decorated functions."""

    __name__: str
    __doc__: str | None

    def __call__(self, *args: Any, **kwargs: Any) -> Awaitable[R]: ...


async def redirect[R](
    route: RouteFunction[R], success: str | None = None, error: str | None = None, **kwargs: Any
) -> response.Response:
    """Redirect to a route with a success or error message."""
    if success is not None:
        await quart.flash(success, "success")
    elif error is not None:
        await quart.flash(error, "error")
    return quart.redirect(util.as_url(route, **kwargs))
