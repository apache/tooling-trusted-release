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

import asfquart.base as base

import atr.blueprints.get as get
import atr.db as db
import atr.mapping as mapping
import atr.models.sql as sql
import atr.shared as shared
import atr.web as web


@get.committer("/compose/<project_name>/<version_name>")
async def selected(session: web.Committer, project_name: str, version_name: str) -> web.WerkzeugResponse | str:
    """Show the contents of the release candidate draft."""
    await session.check_access(project_name)

    async with db.session() as data:
        release = await data.release(
            project_name=project_name,
            version=version_name,
            _committee=True,
            _project_release_policy=True,
        ).demand(base.ASFQuartException("Release does not exist", errorcode=404))
    if release.phase != sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
        return await mapping.release_as_redirect(session, release)
    return await shared.check(session, release)
