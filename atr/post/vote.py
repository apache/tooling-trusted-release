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
import werkzeug.wrappers.response as response

import atr.blueprints.post as post
import atr.forms as forms
import atr.get.vote as get_vote
import atr.models.sql as sql
import atr.shared.vote as shared_vote
import atr.storage as storage
import atr.web as web


@post.committer("/vote/<project_name>/<version_name>")
async def selected_post(session: web.Committer, project_name: str, version_name: str) -> response.Response:
    """Handle submission of a vote."""
    await session.check_access(project_name)

    # Ensure the release exists and is in the correct phase
    release = await session.release(project_name, version_name, phase=sql.ReleasePhase.RELEASE_CANDIDATE)

    if release.committee is None:
        raise ValueError("Release has no committee")

    # Set up form choices
    async with storage.write() as write:
        try:
            if release.committee.is_podling:
                _wacm = write.as_committee_member("incubator")
            else:
                _wacm = write.as_committee_member(release.committee.name)
            potency = "Binding"
        except storage.AccessError:
            # Participant, due to session.check_access above
            potency = "Non-binding"

    form = await shared_vote.CastVoteForm.create_form(data=await quart.request.form)
    forms.choices(
        form.vote_value,
        choices=[
            ("+1", f"+1 ({potency})"),
            ("0", "0"),
            ("-1", f"-1 ({potency})"),
        ],
    )

    if await form.validate_on_submit():
        vote = str(form.vote_value.data)
        comment = str(form.vote_comment.data)
        async with storage.write_as_committee_participant(release.committee.name) as wacm:
            email_recipient, error_message = await wacm.vote.send_user_vote(release, vote, comment, session.fullname)
        if error_message:
            return await session.redirect(
                get_vote.selected, project_name=project_name, version_name=version_name, error=error_message
            )

        success_message = f"Sending your vote to {email_recipient}."
        return await session.redirect(
            get_vote.selected, project_name=project_name, version_name=version_name, success=success_message
        )
    else:
        error_message = "Invalid vote submission"
        if form.errors:
            error_details = "; ".join([f"{field}: {', '.join(errs)}" for field, errs in form.errors.items()])
            error_message = f"{error_message}: {error_details}"

        return await session.redirect(
            get_vote.selected, project_name=project_name, version_name=version_name, error=error_message
        )
