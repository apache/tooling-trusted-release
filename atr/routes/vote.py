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

import enum
import json
import logging
import time
from collections.abc import Generator
from typing import Final

import aiohttp
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.routes.compose as compose
import atr.routes.resolve as resolve
import atr.schema as schema
import atr.tasks.message as message
import atr.template as template
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
}


class CastVoteForm(util.QuartFormTyped):
    """Form for casting a vote."""

    vote_value = wtforms.RadioField(
        "Your vote",
        choices=[("+1", "+1 (Binding)"), ("0", "0"), ("-1", "-1 (Binding)")],
        validators=[wtforms.validators.InputRequired("A vote value (+1, 0, -1) is required.")],
    )
    vote_comment = wtforms.TextAreaField("Comment (optional)", validators=[wtforms.validators.Optional()])
    submit = wtforms.SubmitField("Submit vote")


class ResolveVoteForm(util.QuartFormTyped):
    """Form for resolving a vote."""

    email_body = wtforms.TextAreaField("Email body", render_kw={"rows": 24})
    vote_result = wtforms.RadioField(
        "Vote result",
        choices=[("passed", "Passed"), ("failed", "Failed")],
        validators=[wtforms.validators.InputRequired("Vote result is required")],
    )
    submit = wtforms.SubmitField("Resolve vote")


class Vote(enum.Enum):
    YES = "Yes"
    NO = "No"
    ABSTAIN = "-"
    UNKNOWN = "?"


class VoteStatus(enum.Enum):
    BINDING = "Binding"
    COMMITTER = "Committer"
    CONTRIBUTOR = "Contributor"
    UNKNOWN = "Unknown"


class VoteEmail(schema.Strict):
    asf_uid_or_email: str
    from_email: str
    status: VoteStatus
    asf_eid: str
    iso_datetime: str
    vote: Vote
    quotation: str
    updated: bool


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
        archive_url = await task_archive_url_cached(task_mid)

    form = await CastVoteForm.create_form()
    hidden_form = await util.HiddenFieldForm.create_form()
    hidden_form.hidden_field.data = archive_url or ""
    hidden_form.submit.label.text = "Tabulate votes"
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
    asf_uid = session.uid
    full_name = session.fullname

    release = await session.release(
        project_name,
        version_name,
        phase=models.ReleasePhase.RELEASE_CANDIDATE,
        with_release_policy=True,
        with_project_release_policy=True,
    )
    hidden_form = await util.HiddenFieldForm.create_form()
    tabulated_votes = None
    summary = None
    passed = None
    outcome = None
    committee = None
    thread_id = None
    fetch_error = None
    if await hidden_form.validate_on_submit():
        # TODO: Just pass the thread_id itself instead?
        archive_url = hidden_form.hidden_field.data or ""
        thread_id = archive_url.split("/")[-1]
        if thread_id:
            try:
                committee = await _tabulate_vote_committee(thread_id, release)
            except util.FetchError as e:
                fetch_error = f"Failed to fetch thread metadata: {e}"
            else:
                start_unixtime, tabulated_votes = await _tabulate_votes(committee, thread_id)
                summary = _tabulate_vote_summary(tabulated_votes)
                passed, outcome = _tabulate_vote_outcome(release, start_unixtime, tabulated_votes)
        else:
            fetch_error = "The vote thread could not yet be found."
    resolve_form = await ResolveVoteForm.create_form()
    if (
        (committee is None)
        or (tabulated_votes is None)
        or (summary is None)
        or (passed is None)
        or (outcome is None)
        or (thread_id is None)
    ):
        resolve_form.email_body.render_kw = {"rows": 12}
    else:
        resolve_form.email_body.data = _tabulate_vote_resolution(
            committee, release, tabulated_votes, summary, passed, outcome, full_name, asf_uid, thread_id
        )
        resolve_form.vote_result.data = "passed" if passed else "failed"
    return await template.render(
        "vote-tabulate.html",
        release=release,
        tabulated_votes=tabulated_votes,
        summary=summary,
        outcome=outcome,
        resolve_form=resolve_form,
        fetch_error=fetch_error,
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


async def _tabulate_votes(
    committee: models.Committee | None, thread_id: str
) -> tuple[int | None, dict[str, VoteEmail]]:
    """Tabulate votes."""
    import logging

    start = time.perf_counter_ns()
    email_to_uid = await util.email_to_uid_map()
    end = time.perf_counter_ns()
    logging.info(f"LDAP search took {(end - start) / 1000000} ms")
    logging.info(f"Email addresses from LDAP: {len(email_to_uid)}")

    start = time.perf_counter_ns()
    tabulated_votes = {}
    start_unixtime = None
    async for _mid, msg in util.thread_messages(thread_id):
        from_raw = msg.get("from_raw", "")
        ok, from_email_lower, asf_uid = _tabulate_vote_identity(from_raw, email_to_uid)
        if not ok:
            continue

        if asf_uid is not None:
            asf_uid_or_email = asf_uid
            list_raw = msg.get("list_raw", "")
            status = await _tabulate_vote_status(asf_uid, list_raw, committee)
        else:
            asf_uid_or_email = from_email_lower
            status = VoteStatus.UNKNOWN

        if start_unixtime is None:
            epoch = msg.get("epoch", "")
            if epoch:
                start_unixtime = int(epoch)

        subject = msg.get("subject", "")
        if "[RESULT]" in subject:
            break

        body = msg.get("body", "")
        if not body:
            continue

        castings = _tabulate_vote_castings(body)
        if not castings:
            continue

        if len(castings) == 1:
            vote_cast = castings[0][0]
        else:
            vote_cast = Vote.UNKNOWN
        quotation = " // ".join([c[1] for c in castings])

        vote_email = VoteEmail(
            asf_uid_or_email=asf_uid_or_email,
            from_email=from_email_lower,
            status=status,
            asf_eid=msg.get("mid", ""),
            iso_datetime=msg.get("date", ""),
            vote=vote_cast,
            quotation=quotation,
            updated=asf_uid_or_email in tabulated_votes,
        )
        tabulated_votes[asf_uid_or_email] = vote_email
    end = time.perf_counter_ns()
    logging.info(f"Tabulated votes: {len(tabulated_votes)}")
    logging.info(f"Tabulation took {(end - start) / 1000000} ms")

    return start_unixtime, tabulated_votes


def _tabulate_vote_break(line: str) -> bool:
    if line == "-- ":
        # Start of a signature
        return True
    if line.startswith("On ") and (line[6:8] == ", "):
        # Start of a quoted email
        return True
    if line.startswith("From: "):
        # Start of a quoted email
        return True
    if line.startswith("________"):
        # This is sometimes used as an "On " style quotation marker
        return True
    return False


def _tabulate_vote_castings(body: str) -> list[tuple[Vote, str]]:
    castings = []
    for line in body.split("\n"):
        if _tabulate_vote_continue(line):
            continue
        if _tabulate_vote_break(line):
            break

        plus_one = line.startswith("+1") or " +1" in line
        minus_one = line.startswith("-1") or " -1" in line
        # We must be more stringent about zero votes, can't just check for "0" in line
        zero = line in {"0", "-0", "+0"} or line.startswith("0 ") or line.startswith("+0 ") or line.startswith("-0 ")
        if (plus_one and minus_one) or (plus_one and zero) or (minus_one and zero):
            # Confusing result
            continue
        if plus_one:
            castings.append((Vote.YES, line))
        elif minus_one:
            castings.append((Vote.NO, line))
        elif zero:
            castings.append((Vote.ABSTAIN, line))
    return castings


async def _tabulate_vote_committee(thread_id: str, release: models.Release) -> models.Committee | None:
    committee = None
    if release.project is not None:
        committee = release.project.committee
    if util.is_dev_environment():
        async for _mid, msg in util.thread_messages(thread_id):
            list_raw = msg.get("list_raw", "")
            committee_label = list_raw.split(".apache.org", 1)[0].split(".", 1)[-1]
            async with db.session() as data:
                committee = await data.committee(name=committee_label).get()
            break
    return committee


def _tabulate_vote_continue(line: str) -> bool:
    explanation_indicators = [
        "[ ] +1",
        "[ ] -1",
        "binding +1 votes",
        "binding -1 votes",
    ]
    if any((indicator in line) for indicator in explanation_indicators):
        # These indicators are used by the [VOTE] OP to indicate how to vote
        return True

    if line.startswith(">"):
        # Used to quote other emails
        return True
    return False


def _tabulate_vote_identity(from_raw: str, email_to_uid: dict[str, str]) -> tuple[bool, str, str | None]:
    from_email_lower = util.email_from_uid(from_raw)
    if not from_email_lower:
        return False, "", None
    from_email_lower = from_email_lower.removesuffix(".invalid")
    asf_uid = None
    if from_email_lower.endswith("@apache.org"):
        asf_uid = from_email_lower.split("@")[0]
    elif from_email_lower in email_to_uid:
        asf_uid = email_to_uid[from_email_lower]
    return True, from_email_lower, asf_uid


def _tabulate_vote_outcome(
    release: models.Release, start_unixtime: int | None, tabulated_votes: dict[str, VoteEmail]
) -> tuple[bool, str]:
    now = int(time.time())
    duration_hours = 0
    if start_unixtime is not None:
        duration_hours = (now - start_unixtime) / 3600

    min_duration_hours = 72
    if release.project is not None:
        if release.project.release_policy is not None:
            min_duration_hours = release.project.release_policy.min_hours or None
    duration_hours_remaining = None
    if min_duration_hours is not None:
        duration_hours_remaining = min_duration_hours - duration_hours

    binding_plus_one = 0
    binding_minus_one = 0
    for vote_email in tabulated_votes.values():
        if vote_email.status != VoteStatus.BINDING:
            continue
        if vote_email.vote == Vote.YES:
            binding_plus_one += 1
        elif vote_email.vote == Vote.NO:
            binding_minus_one += 1

    return _tabulate_vote_outcome_format(duration_hours_remaining, binding_plus_one, binding_minus_one)


def _tabulate_vote_outcome_format(
    duration_hours_remaining: float | int | None, binding_plus_one: int, binding_minus_one: int
) -> tuple[bool, str]:
    outcome_passed = (binding_plus_one >= 3) and (binding_plus_one > binding_minus_one)
    if not outcome_passed:
        if (duration_hours_remaining is not None) and (duration_hours_remaining > 0):
            msg = f"The vote is still open for {duration_hours_remaining} hours, but the vote would fail if closed now."
        elif duration_hours_remaining is None:
            msg = "The vote would fail if closed now."
        else:
            msg = "The vote failed."
        return False, msg

    if (duration_hours_remaining is not None) and (duration_hours_remaining > 0):
        msg = f"The vote is still open for {duration_hours_remaining} hours, but the vote would pass if closed now."
    else:
        msg = "The vote passed."
    return True, msg


def _tabulate_vote_resolution(
    committee: models.Committee,
    release: models.Release,
    tabulated_votes: dict[str, VoteEmail],
    summary: dict[str, int],
    passed: bool,
    outcome: str,
    full_name: str,
    asf_uid: str,
    thread_id: str,
) -> str:
    """Generate a resolution email body."""
    body = [f"Dear {committee.display_name} participants,", ""]
    outcome = "passed" if passed else "failed"
    body.append(f"The vote on {release.project.name} {release.version} {outcome}.")
    body.append("")

    body.append("The vote thread is archived at the following URL:")
    body.append("")
    body.append(f"https://lists.apache.org/thread/{thread_id}")
    body.append("")

    body.extend(_tabulate_vote_resolution_votes(tabulated_votes, {VoteStatus.BINDING}))

    binding_total = summary["binding_votes"]
    body.append(f"There were {binding_total} binding {'vote' if (binding_total == 1) else 'votes'}.")
    body.append("")

    binding_yes = summary["binding_votes_yes"]
    binding_no = summary["binding_votes_no"]
    binding_abstain = summary["binding_votes_abstain"]
    body.append(f"Of these binding votes, {binding_yes} were +1, {binding_no} were -1, and {binding_abstain} were 0.")
    body.append("")

    body.extend(_tabulate_vote_resolution_votes(tabulated_votes, {VoteStatus.COMMITTER}))
    body.extend(_tabulate_vote_resolution_votes(tabulated_votes, {VoteStatus.CONTRIBUTOR, VoteStatus.UNKNOWN}))

    body.append("Thank you for your participation.")
    body.append("")
    body.append("Sincerely,")
    body.append(f"{full_name} ({asf_uid})")
    return "\n".join(body)


def _tabulate_vote_resolution_votes(tabulated_votes: dict[str, VoteEmail], statuses: set[VoteStatus]) -> Generator[str]:
    header: str | None = f"The {' and '.join(status.value.lower() for status in statuses)} votes were cast as follows:"
    for vote_email in tabulated_votes.values():
        if vote_email.status not in statuses:
            continue
        if header is not None:
            yield header
            yield ""
            header = None
        match vote_email.vote:
            case Vote.YES:
                symbol = "+1"
            case Vote.NO:
                symbol = "-1"
            case Vote.ABSTAIN:
                symbol = "0"
            case Vote.UNKNOWN:
                symbol = "?"
        user_info = vote_email.asf_uid_or_email
        status = vote_email.status.value.lower()
        if vote_email.updated:
            status += ", updated"
        yield f"{symbol} {user_info} ({status})"
    if header is None:
        yield ""


async def _tabulate_vote_status(asf_uid: str, list_raw: str, committee: models.Committee | None) -> VoteStatus:
    status = VoteStatus.UNKNOWN

    if util.is_dev_environment():
        committee_label = list_raw.split(".apache.org", 1)[0].split(".", 1)[-1]
        async with db.session() as data:
            committee = await data.committee(name=committee_label).get()
    if committee is not None:
        if asf_uid in committee.committee_members:
            status = VoteStatus.BINDING
        elif asf_uid in committee.committers:
            status = VoteStatus.COMMITTER
        else:
            status = VoteStatus.CONTRIBUTOR
    return status


def _tabulate_vote_summary(tabulated_votes: dict[str, VoteEmail]) -> dict[str, int]:
    result = {
        "binding_votes": 0,
        "binding_votes_yes": 0,
        "binding_votes_no": 0,
        "binding_votes_abstain": 0,
        "non_binding_votes": 0,
        "non_binding_votes_yes": 0,
        "non_binding_votes_no": 0,
        "non_binding_votes_abstain": 0,
        "unknown_votes": 0,
        "unknown_votes_yes": 0,
        "unknown_votes_no": 0,
        "unknown_votes_abstain": 0,
    }

    for vote_email in tabulated_votes.values():
        if vote_email.status == VoteStatus.BINDING:
            result["binding_votes"] += 1
            result["binding_votes_yes"] += 1 if (vote_email.vote.value == "Yes") else 0
            result["binding_votes_no"] += 1 if (vote_email.vote.value == "No") else 0
            result["binding_votes_abstain"] += 1 if (vote_email.vote.value == "Abstain") else 0
        elif vote_email.status in {VoteStatus.COMMITTER, VoteStatus.CONTRIBUTOR}:
            result["non_binding_votes"] += 1
            result["non_binding_votes_yes"] += 1 if (vote_email.vote.value == "Yes") else 0
            result["non_binding_votes_no"] += 1 if (vote_email.vote.value == "No") else 0
            result["non_binding_votes_abstain"] += 1 if (vote_email.vote.value == "Abstain") else 0
        else:
            result["unknown_votes"] += 1
            result["unknown_votes_yes"] += 1 if (vote_email.vote.value == "Yes") else 0
            result["unknown_votes_no"] += 1 if (vote_email.vote.value == "No") else 0
            result["unknown_votes_abstain"] += 1 if (vote_email.vote.value == "Abstain") else 0

    return result


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
