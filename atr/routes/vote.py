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
import quart
import werkzeug.wrappers.response as response

import atr.db as db
import atr.db.interaction as interaction
import atr.forms as forms
import atr.log as log
import atr.models.results as results
import atr.models.sql as sql
import atr.route as route
import atr.routes.compose as compose
import atr.routes.mapping as mapping
import atr.storage as storage
import atr.util as util


class CastVoteForm(forms.Typed):
    """Form for casting a vote."""

    vote_value = forms.radio("Your vote")
    vote_comment = forms.textarea("Comment (optional)", optional=True)
    submit = forms.submit("Submit vote")


@route.committer("/vote/<project_name>/<version_name>")
async def selected(session: route.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Show the contents of the release candidate draft."""
    await session.check_access(project_name)

    async with db.session() as data:
        release = await data.release(
            project_name=project_name,
            version=version_name,
            _committee=True,
            _project_release_policy=True,
        ).demand(base.ASFQuartException("Release does not exist", errorcode=404))
    if release.phase != sql.ReleasePhase.RELEASE_CANDIDATE:
        return await mapping.release_as_redirect(session, release)
    latest_vote_task = await interaction.release_latest_vote_task(release)
    archive_url = None
    task_mid = None

    if latest_vote_task is not None:
        if util.is_dev_environment():
            log.warning("Setting vote task to completed in dev environment")
            latest_vote_task.status = sql.TaskStatus.COMPLETED
            latest_vote_task.result = results.VoteInitiate(
                kind="vote_initiate",
                message="Vote announcement email sent successfully",
                email_to="example@example.org.INVALID",
                vote_end="2025-07-01 12:00:00",
                subject="Test vote",
                mid=interaction.TEST_MID,
                mail_send_warnings=[],
            )

        # Move task_mid_get here?
        task_mid = interaction.task_mid_get(latest_vote_task)
        archive_url = await interaction.task_archive_url_cached(task_mid)

    # Special form for the [ Resolve vote ] button, to make it POST
    hidden_form = await forms.Hidden.create_form()
    hidden_form.hidden_field.data = archive_url or ""
    hidden_form.submit.label.text = "Resolve vote"

    if release.committee is None:
        raise ValueError("Release has no committee")

    # Form to cast a vote
    form = await CastVoteForm.create_form()
    async with storage.write() as write:
        try:
            if release.committee.is_podling:
                _wacm = write.as_committee_member("incubator")
            else:
                _wacm = write.as_committee_member(release.committee.name)
            potency = "Binding"
        except storage.AccessError:
            potency = "Non-binding"
    forms.choices(
        form.vote_value,
        choices=[
            ("+1", f"+1 ({potency})"),
            ("0", "0"),
            ("-1", f"-1 ({potency})"),
        ],
    )

    return await compose.check(
        session,
        release,
        task_mid=task_mid,
        form=form,
        hidden_form=hidden_form,
        archive_url=archive_url,
        vote_task=latest_vote_task,
    )


@route.committer("/vote/<project_name>/<version_name>", methods=["POST"])
async def selected_post(session: route.CommitterSession, project_name: str, version_name: str) -> response.Response:
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
            potency = "Non-binding"

    form = await CastVoteForm.create_form(data=await quart.request.form)
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
                selected, project_name=project_name, version_name=version_name, error=error_message
            )

        success_message = f"Sending your vote to {email_recipient}."
        return await session.redirect(
            selected, project_name=project_name, version_name=version_name, success=success_message
        )
    else:
        error_message = "Invalid vote submission"
        if form.errors:
            error_details = "; ".join([f"{field}: {', '.join(errs)}" for field, errs in form.errors.items()])
            error_message = f"{error_message}: {error_details}"

        return await session.redirect(
            selected, project_name=project_name, version_name=version_name, error=error_message
        )
