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
import logging
import time
from collections.abc import Generator

import atr.db as db
import atr.db.models as models
import atr.schema as schema
import atr.util as util


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


async def votes(committee: models.Committee | None, thread_id: str) -> tuple[int | None, dict[str, VoteEmail]]:
    """Tabulate votes."""
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
        ok, from_email_lower, asf_uid = _vote_identity(from_raw, email_to_uid)
        if not ok:
            continue

        if asf_uid is not None:
            asf_uid_or_email = asf_uid
            list_raw = msg.get("list_raw", "")
            status = await _vote_status(asf_uid, list_raw, committee)
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

        castings = _vote_castings(body)
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


async def vote_committee(thread_id: str, release: models.Release) -> models.Committee | None:
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


def vote_outcome(
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

    return _vote_outcome_format(duration_hours_remaining, binding_plus_one, binding_minus_one)


def vote_resolution(
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
    return "\n".join(
        _vote_resolution_body(
            committee, release, tabulated_votes, summary, passed, outcome, full_name, asf_uid, thread_id
        )
    )


def vote_summary(tabulated_votes: dict[str, VoteEmail]) -> dict[str, int]:
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


def _vote_break(line: str) -> bool:
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


def _vote_castings(body: str) -> list[tuple[Vote, str]]:
    castings = []
    for line in body.split("\n"):
        if _vote_continue(line):
            continue
        if _vote_break(line):
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


def _vote_continue(line: str) -> bool:
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


def _vote_identity(from_raw: str, email_to_uid: dict[str, str]) -> tuple[bool, str, str | None]:
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


def _vote_outcome_format(
    duration_hours_remaining: float | int | None, binding_plus_one: int, binding_minus_one: int
) -> tuple[bool, str]:
    outcome_passed = (binding_plus_one >= 3) and (binding_plus_one > binding_minus_one)
    if not outcome_passed:
        if (duration_hours_remaining is not None) and (duration_hours_remaining > 0):
            rounded = round(duration_hours_remaining, 2)
            msg = f"The vote is still open for {rounded} hours, but it would fail if closed now."
        elif duration_hours_remaining is None:
            msg = "The vote would fail if closed now."
        else:
            msg = "The vote failed."
        return False, msg

    if (duration_hours_remaining is not None) and (duration_hours_remaining > 0):
        rounded = round(duration_hours_remaining, 2)
        msg = f"The vote is still open for {rounded} hours, but it would pass if closed now."
    else:
        msg = "The vote passed."
    return True, msg


def _vote_resolution_body(
    committee: models.Committee,
    release: models.Release,
    tabulated_votes: dict[str, VoteEmail],
    summary: dict[str, int],
    passed: bool,
    outcome: str,
    full_name: str,
    asf_uid: str,
    thread_id: str,
) -> Generator[str]:
    committee_name = committee.display_name
    if release.podling_thread_id:
        committee_name = "Incubator"
    yield f"Dear {committee_name} participants,"
    yield ""
    outcome = "passed" if passed else "failed"
    yield f"The vote on {release.project.name} {release.version} {outcome}."
    yield ""

    if release.podling_thread_id:
        yield "The previous round of voting is archived at the following URL:"
        yield ""
        yield f"https://lists.apache.org/thread/{release.podling_thread_id}"
        yield ""
        yield "The current vote thread is archived at the following URL:"
    else:
        yield "The vote thread is archived at the following URL:"
    yield ""
    yield f"https://lists.apache.org/thread/{thread_id}"
    yield ""

    yield from _vote_resolution_body_votes(tabulated_votes, summary)
    yield "Thank you for your participation."
    yield ""
    yield "Sincerely,"
    yield f"{full_name} ({asf_uid})"


def _vote_resolution_body_votes(tabulated_votes: dict[str, VoteEmail], summary: dict[str, int]) -> Generator[str]:
    yield from _vote_resolution_votes(tabulated_votes, {VoteStatus.BINDING})

    binding_total = summary["binding_votes"]
    were_word = "was" if (binding_total == 1) else "were"
    votes_word = "vote" if (binding_total == 1) else "votes"
    yield f"There {were_word} {binding_total} binding {votes_word}."
    yield ""

    binding_yes = summary["binding_votes_yes"]
    binding_no = summary["binding_votes_no"]
    binding_abstain = summary["binding_votes_abstain"]
    yield f"Of these binding votes, {binding_yes} were +1, {binding_no} were -1, and {binding_abstain} were 0."
    yield ""

    yield from _vote_resolution_votes(tabulated_votes, {VoteStatus.COMMITTER})
    yield from _vote_resolution_votes(tabulated_votes, {VoteStatus.CONTRIBUTOR, VoteStatus.UNKNOWN})


def _vote_resolution_votes(tabulated_votes: dict[str, VoteEmail], statuses: set[VoteStatus]) -> Generator[str]:
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


async def _vote_status(asf_uid: str, list_raw: str, committee: models.Committee | None) -> VoteStatus:
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
