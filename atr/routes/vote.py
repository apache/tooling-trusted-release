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

import atr.db as db
import atr.db.interaction as interaction
import atr.forms as forms
import atr.log as log
import atr.models.results as results
import atr.models.sql as sql
import atr.routes as routes
import atr.routes.compose as compose
import atr.storage as storage
import atr.tasks.message as message
import atr.util as util


class CastVoteForm(forms.Typed):
    """Form for casting a vote."""

    vote_value = forms.radio("Your vote")
    vote_comment = forms.textarea("Comment (optional)", optional=True)
    submit = forms.submit("Submit vote")


@routes.committer("/vote/<project_name>/<version_name>")
async def selected(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Show the contents of the release candidate draft."""
    await session.check_access(project_name)

    release = await session.release(
        project_name,
        version_name,
        with_committee=True,
        phase=sql.ReleasePhase.RELEASE_CANDIDATE,
        with_project_release_policy=True,
    )
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


@routes.committer("/vote/<project_name>/<version_name>", methods=["POST"])
async def selected_post(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response:
    """Handle submission of a vote."""
    await session.check_access(project_name)

    form = await CastVoteForm.create_form(data=await quart.request.form)

    if await form.validate_on_submit():
        # Ensure the release exists and is in the correct phase
        release = await session.release(project_name, version_name, phase=sql.ReleasePhase.RELEASE_CANDIDATE)

        vote = str(form.vote_value.data)
        comment = str(form.vote_comment.data)
        email_recipient, error_message = await _send_vote(session, release, vote, comment)
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


async def _send_vote(
    session: routes.CommitterSession,
    release: sql.Release,
    vote: str,
    comment: str,
) -> tuple[str, str]:
    # Get the email thread
    latest_vote_task = await interaction.release_latest_vote_task(release)
    if latest_vote_task is None:
        return "", "No vote task found."
    vote_thread_mid = interaction.task_mid_get(latest_vote_task)
    if vote_thread_mid is None:
        return "", "No vote thread found."

    # Construct the reply email
    original_subject = latest_vote_task.task_args["subject"]

    # Arguments for the task to cast a vote
    email_recipient = latest_vote_task.task_args["email_to"]
    email_sender = f"{session.uid}@apache.org"
    subject = f"Re: {original_subject}"
    body = [f"{vote.lower()} ({session.uid}) {session.fullname}"]
    if comment:
        body.append(f"{comment}")
        # Only include the signature if there is a comment
        body.append(f"-- \n{session.fullname} ({session.uid})")
    body_text = "\n\n".join(body)
    in_reply_to = vote_thread_mid

    # TODO: Move this to the storage interface
    task = sql.Task(
        status=sql.TaskStatus.QUEUED,
        task_type=sql.TaskType.MESSAGE_SEND,
        task_args=message.Send(
            email_sender=email_sender,
            email_recipient=email_recipient,
            subject=subject,
            body=body_text,
            in_reply_to=in_reply_to,
        ).model_dump(),
        asf_uid=util.unwrap(session.uid),
        project_name=release.project.name,
        version_name=release.version,
    )
    async with db.session() as data:
        data.add(task)
        await data.flush()
        await data.commit()

    return email_recipient, ""
