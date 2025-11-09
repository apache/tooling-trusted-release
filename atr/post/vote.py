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

import quart

import atr.blueprints.post as post
import atr.get as get
import atr.models.sql as sql
import atr.shared as shared
import atr.storage as storage
import atr.web as web


@post.committer("/vote/<project_name>/<version_name>")
@post.form(shared.vote.CastVoteForm)
async def selected_post(
    session: web.Committer, cast_vote_form: shared.vote.CastVoteForm, project_name: str, version_name: str
) -> web.WerkzeugResponse:
    await session.check_access(project_name)

    release = await session.release(project_name, version_name, phase=sql.ReleasePhase.RELEASE_CANDIDATE)

    if release.committee is None:
        raise ValueError("Release has no committee")

    vote = cast_vote_form.decision
    comment = cast_vote_form.comment

    async with storage.write_as_committee_participant(release.committee.name) as wacm:
        email_recipient, error_message = await wacm.vote.send_user_vote(release, vote, comment, session.fullname)

    if error_message:
        await quart.flash(error_message, "error")
        return await session.redirect(get.vote.selected, project_name=project_name, version_name=version_name)

    success_message = f"Sending your vote to {email_recipient}."
    await quart.flash(success_message, "success")
    return await session.redirect(get.vote.selected, project_name=project_name, version_name=version_name)
