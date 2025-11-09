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

import atr.blueprints.post as post
import atr.db as db
import atr.db.interaction as interaction
import atr.get as get
import atr.log as log
import atr.shared as shared
import atr.storage as storage
import atr.util as util
import atr.web as web


@post.committer("/voting/<project_name>/<version_name>/<revision>")
@post.form(shared.voting.StartVotingForm)
async def selected_revision(
    session: web.Committer,
    start_voting_form: shared.voting.StartVotingForm,
    project_name: str,
    version_name: str,
    revision: str,
) -> web.WerkzeugResponse | str:
    await session.check_access(project_name)

    async with db.session() as data:
        match await interaction.release_ready_for_vote(
            session, project_name, version_name, revision, data, manual_vote=False
        ):
            case str() as error:
                return await session.redirect(
                    get.compose.selected,
                    error=error,
                    project_name=project_name,
                    version_name=version_name,
                    revision=revision,
                )
            case (release, committee):
                pass

        permitted_recipients = util.permitted_voting_recipients(session.uid, committee.name)
        if start_voting_form.mailing_list not in permitted_recipients:
            return await session.form_error(
                "mailing_list",
                f"Invalid mailing list selection: {start_voting_form.mailing_list}",
            )

        async with storage.write_as_committee_participant(committee.name) as wacp:
            _task = await wacp.vote.start(
                start_voting_form.mailing_list,
                project_name,
                version_name,
                revision,
                start_voting_form.vote_duration,
                start_voting_form.subject,
                start_voting_form.body,
                session.uid,
                session.fullname,
                release=release,
                promote=True,
                permitted_recipients=permitted_recipients,
            )

        log.info(f"Vote email will be sent to: {start_voting_form.mailing_list}")
        return await session.redirect(
            get.vote.selected,
            success=f"The vote announcement email will soon be sent to {start_voting_form.mailing_list}.",
            project_name=project_name,
            version_name=version_name,
        )
