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

from collections.abc import Callable

import werkzeug.wrappers.response as response

import atr.get as get
import atr.models.sql as sql
import atr.util as util
import atr.web as web


async def release_as_redirect(
    session: web.Committer,
    release: sql.Release,
) -> response.Response:
    route = release_as_route(release)
    if route is get.release.finished:
        return await session.redirect(route, project_name=release.project.name)
    return await session.redirect(route, project_name=release.project.name, version_name=release.version)


def release_as_route(release: sql.Release) -> Callable:
    match release.phase:
        case sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
            return get.compose.selected
        case sql.ReleasePhase.RELEASE_CANDIDATE:
            return get.vote.selected
        case sql.ReleasePhase.RELEASE_PREVIEW:
            return get.finish.selected
        case sql.ReleasePhase.RELEASE:
            return get.release.finished


def release_as_url(release: sql.Release) -> str:
    route = release_as_route(release)
    if route is get.release.finished:
        return util.as_url(route, project_name=release.project.name)
    return util.as_url(route, project_name=release.project.name, version_name=release.version)
