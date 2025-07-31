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

from typing import Final

import aiohttp
import quart
import werkzeug.wrappers.response as response

import atr.db as db
import atr.forms as forms
import atr.log as log
import atr.models.results as results
import atr.models.sql as sql
import atr.routes as routes
import atr.routes.compose as compose
import atr.routes.resolve as resolve
import atr.tasks.message as message
import atr.util as util

# TEST_MID: Final[str | None] = "CAH5JyZo8QnWmg9CwRSwWY=GivhXW4NiLyeNJO71FKdK81J5-Uw@mail.gmail.com"
TEST_MID: Final[str | None] = None
_THREAD_URLS_FOR_DEVELOPMENT: Final[dict[str, str]] = {
    "CAH5JyZo8QnWmg9CwRSwWY=GivhXW4NiLyeNJO71FKdK81J5-Uw@mail.gmail.com": "https://lists.apache.org/thread/z0o7xnjnyw2o886rxvvq2ql4rdfn754w",
    "818a44a3-6984-4aba-a650-834e86780b43@apache.org": "https://lists.apache.org/thread/619hn4x796mh3hkk3kxg1xnl48dy2s64",
    "CAA9ykM+bMPNk=BOF9hj0O+mjN1igppOJ+pKdZHcAM0ddVi+5_w@mail.gmail.com": "https://lists.apache.org/thread/x0m3p2xqjvflgtkb6oxqysm36cr9l5mg",
    "CAFHDsVzgtfboqYF+a3owaNf+55MUiENWd3g53mU4rD=WHkXGwQ@mail.gmail.com": "https://lists.apache.org/thread/brj0k3g8pq63g8f7xhmfg2rbt1240nts",
    "CAMomwMrvKTQK7K2-OtZTrEO0JjXzO2g5ynw3gSoks_PXWPZfoQ@mail.gmail.com": "https://lists.apache.org/thread/y5rqp5qk6dmo08wlc3g20n862hznc9m8",
    "CANVKqzfLYj6TAVP_Sfsy5vFbreyhKskpRY-vs=F7aLed+rL+uA@mail.gmail.com": "https://lists.apache.org/thread/oy969lhh6wlzd51ovckn8fly9rvpopwh",
    "CAH4123ZwGtkwszhEU7qnMByLa-yvyKz2W+DjH_UChPMuzaa54g@mail.gmail.com": "https://lists.apache.org/thread/7111mqyc25sfqxm6bf4ynwhs0bk0r4ys",
    "CADL1oArKFcXvNb1MJfjN=10-yRfKxgpLTRUrdMM1R7ygaTkdYQ@mail.gmail.com": "https://lists.apache.org/thread/d7119h2qm7jrd5zsbp8ghkk0lpvnnxnw",
    "a1507118-88b1-4b7b-923e-7f2b5330fc01@apache.org": "https://lists.apache.org/thread/gzjd2jv7yod5sk5rgdf4x33g5l3fdf5o",
}


class CastVoteForm(forms.Typed):
    """Form for casting a vote."""

    vote_value = forms.radio("Your vote", choices=[("+1", "+1 (Binding)"), ("0", "0"), ("-1", "-1 (Binding)")])
    vote_comment = forms.textarea("Comment (optional)")
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
    latest_vote_task = await resolve.release_latest_vote_task(release)
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
                mid=TEST_MID,
                mail_send_warnings=[],
            )

        # Move task_mid_get here?
        task_mid = resolve.task_mid_get(latest_vote_task)
        archive_url = await task_archive_url_cached(task_mid)

    form = await CastVoteForm.create_form()
    hidden_form = await forms.Hidden.create_form()
    hidden_form.hidden_field.data = archive_url or ""
    hidden_form.submit.label.text = "Resolve vote"
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


async def task_archive_url_cached(task_mid: str | None) -> str | None:
    if task_mid in _THREAD_URLS_FOR_DEVELOPMENT:
        return _THREAD_URLS_FOR_DEVELOPMENT[task_mid]

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


async def _send_vote(
    session: routes.CommitterSession,
    release: sql.Release,
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
        log.exception("Failed to get archive URL for task %s", task_mid)
        return None
