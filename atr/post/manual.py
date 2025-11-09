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

import atr.blueprints.post as post
import atr.db as db
import atr.db.interaction as interaction
import atr.get.vote as vote
import atr.storage as storage
import atr.web as web


@post.committer("/manual/<project_name>/<version_name>/<revision>")
@post.empty()
async def selected_revision(
    session: web.Committer, project_name: str, version_name: str, revision: str
) -> web.WerkzeugResponse | str:
    await session.check_access(project_name)

    async with db.session() as data:
        match await interaction.release_ready_for_vote(
            session, project_name, version_name, revision, data, manual_vote=True
        ):
            case str() as error:
                return await session.redirect(
                    vote.selected,
                    error=error,
                    project_name=project_name,
                    version_name=version_name,
                )
            case (release, _committee):
                pass

        async with storage.write(session) as write:
            wacp = await write.as_project_committee_participant(release.project_name)
            error = await wacp.release.promote_to_candidate(release.name, revision, vote_manual=True)

        if error:
            return await session.redirect(
                vote.selected,
                error=error,
                project_name=project_name,
                version_name=version_name,
            )

        return await session.redirect(
            vote.selected,
            success="The manual vote process has been started.",
            project_name=project_name,
            version_name=version_name,
        )
