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

import json
import logging

import aiohttp
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.routes.compose as compose
import atr.routes.resolve as resolve
import atr.tasks.message as message
import atr.template as template
import atr.util as util

TEST_MID = "CAH5JyZo8QnWmg9CwRSwWY=GivhXW4NiLyeNJO71FKdK81J5-Uw@mail.gmail.com"


class CastVoteForm(util.QuartFormTyped):
    """Form for casting a vote."""

    vote_value = wtforms.RadioField(
        "Your vote",
        choices=[("+1", "+1 (Binding)"), ("0", "0"), ("-1", "-1 (Binding)")],
        validators=[wtforms.validators.InputRequired("A vote value (+1, 0, -1) is required.")],
    )
    vote_comment = wtforms.TextAreaField("Comment (optional)", validators=[wtforms.validators.Optional()])
    submit = wtforms.SubmitField("Submit vote")


@routes.committer("/vote/<project_name>/<version_name>")
async def selected(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Show the contents of the release candidate draft."""
    await session.check_access(project_name)

    release = await session.release(
        project_name, version_name, with_committee=True, phase=models.ReleasePhase.RELEASE_CANDIDATE
    )
    latest_vote_task = await resolve.release_latest_vote_task(release)
    archive_url = None
    task_mid = None

    if latest_vote_task is not None:
        if util.is_dev_environment():
            logging.warning("Setting vote task to completed in dev environment")
            latest_vote_task.status = models.TaskStatus.COMPLETED
            latest_vote_task.result = [json.dumps({"mid": TEST_MID})]

        # Move task_mid_get here?
        task_mid = resolve.task_mid_get(latest_vote_task)
        archive_url = await _task_archive_url_cached(task_mid)

    form = await CastVoteForm.create_form()
    empty_form = await util.QuartFormTyped.create_form()
    return await compose.check(
        session,
        release,
        task_mid=task_mid,
        form=form,
        empty_form=empty_form,
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
        release = await session.release(project_name, version_name, phase=models.ReleasePhase.RELEASE_CANDIDATE)

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


@routes.committer("/vote/<project_name>/<version_name>/tabulate", methods=["POST"])
async def tabulate(session: routes.CommitterSession, project_name: str, version_name: str) -> str:
    """Tabulate votes."""
    await session.check_access(project_name)

    release = await session.release(project_name, version_name, phase=models.ReleasePhase.RELEASE_CANDIDATE)
    await _tabulate_votes(session, release)
    return await template.render("vote-tabulate.html", release=release)


async def _send_vote(
    session: routes.CommitterSession,
    release: models.Release,
    vote: str,
    comment: str,
) -> tuple[str, str]:
    # Get the email thread
    latest_vote_task = await resolve.release_latest_vote_task(release)
    if latest_vote_task is None:
        return "", "No vote task found."
    vote_thread_mid = resolve.task_mid_get(latest_vote_task)
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

    task = models.Task(
        status=models.TaskStatus.QUEUED,
        task_type=models.TaskType.MESSAGE_SEND,
        task_args=message.Send(
            email_sender=email_sender,
            email_recipient=email_recipient,
            subject=subject,
            body=body_text,
            in_reply_to=in_reply_to,
        ).model_dump(),
        project_name=release.project.name,
        version_name=release.version,
    )
    async with db.session() as data:
        data.add(task)
        await data.flush()
        await data.commit()

    return email_recipient, ""


async def _tabulate_votes(session: routes.CommitterSession, release: models.Release) -> None:
    """Tabulate votes."""
    pass


async def _task_archive_url(task_mid: str) -> str | None:
    if "@" not in task_mid:
        return None

    # TODO: This List ID will be dynamic when we allow posting to arbitrary lists
    lid = "user-tests.tooling.apache.org"
    url = f"https://lists.apache.org/api/email.lua?id=%3C{task_mid}%3E&listid=%3C{lid}%3E"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                response.raise_for_status()
                # TODO: Check whether this blocks from network
                email_data = await response.json()
        mid = email_data["mid"]
        if not isinstance(mid, str):
            return None
        return "https://lists.apache.org/thread/" + mid
    except Exception:
        logging.exception("Failed to get archive URL for task %s", task_mid)
        return None


async def _task_archive_url_cached(task_mid: str | None) -> str | None:
    dev_urls = {
        "CAH5JyZo8QnWmg9CwRSwWY=GivhXW4NiLyeNJO71FKdK81J5-Uw@mail.gmail.com": "https://lists.apache.org/thread/z0o7xnjnyw2o886rxvvq2ql4rdfn754w",
        "818a44a3-6984-4aba-a650-834e86780b43@apache.org": "https://lists.apache.org/thread/619hn4x796mh3hkk3kxg1xnl48dy2s64",
    }
    if task_mid in dev_urls:
        return dev_urls[task_mid]

    if task_mid is None:
        return None
    if "@" not in task_mid:
        return None

    async with db.session() as data:
        url = await data.ns_text_get(
            "mid-url-cache",
            task_mid,
        )
        if url is not None:
            return url

    url = await _task_archive_url(task_mid)
    if url is not None:
        await data.ns_text_set(
            "mid-url-cache",
            task_mid,
            url,
        )

    return url
