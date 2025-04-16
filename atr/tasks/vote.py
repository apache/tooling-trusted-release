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

import datetime
import json
import logging
import os
from typing import Any, Final

import aiofiles
import pydantic

import atr.db as db
import atr.mail as mail
import atr.tasks.checks as checks

# Configure detailed logging
_LOGGER: Final = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)


class Initiate(pydantic.BaseModel):
    """Arguments for the task to start a vote."""

    release_name: str = pydantic.Field(..., description="The name of the release to vote on")
    email_to: str = pydantic.Field(..., description="The mailing list address to send the vote email to")
    vote_duration: int = pydantic.Field(..., description="Duration of the vote in hours")
    initiator_id: str = pydantic.Field(..., description="ASF ID of the vote initiator")
    gpg_key_fingerprint: str | None = pydantic.Field(
        ..., description="GPG key fingerprint of the initiator, if available"
    )
    subject: str = pydantic.Field(..., description="Subject line for the vote email")
    body: str = pydantic.Field(..., description="Body content for the vote email")


class VoteInitiationError(Exception): ...


@checks.with_model(Initiate)
async def initiate(args: Initiate) -> str | None:
    """Initiate a vote for a release."""
    try:
        result_data = await _initiate_core_logic(args)
        return json.dumps(result_data)

    except VoteInitiationError as e:
        _LOGGER.error(f"Vote initiation failed: {e}")
        raise
    except Exception as e:
        _LOGGER.exception(f"Unexpected error during vote initiation: {e}")
        raise


async def _initiate_core_logic(args: Initiate) -> dict[str, Any]:
    """Get arguments, create an email, and then send it to the recipient."""
    tooling_test_recipients = ["user-tests"]
    _LOGGER.info("Starting initiate_core")

    # Validate arguments
    if not args.email_to.endswith("@apache.org") or args.email_to.endswith(".apache.org"):
        raise VoteInitiationError("Invalid destination email address")

    async with db.session() as data:
        release = await data.release(name=args.release_name, _project=True, _committee=True).demand(
            VoteInitiationError(f"Release {args.release_name} not found")
        )

    # Calculate vote end date
    vote_duration_hours = args.vote_duration
    vote_start = datetime.datetime.now(datetime.UTC)
    vote_end = vote_start + datetime.timedelta(hours=vote_duration_hours)

    # Format dates for email
    vote_end_str = vote_end.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Load and set DKIM key
    try:
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        dkim_path = os.path.join(project_root, "state", "dkim.private")

        async with aiofiles.open(dkim_path) as f:
            dkim_key = await f.read()
            mail.set_secret_key(dkim_key.strip())
            _LOGGER.info("DKIM key loaded and set successfully")
    except Exception as e:
        error_msg = f"Failed to load DKIM key: {e}"
        _LOGGER.error(error_msg)
        raise VoteInitiationError(error_msg)

    # Get PMC and project details
    if release.committee is None:
        error_msg = "Release has no associated committee"
        _LOGGER.error(error_msg)
        raise VoteInitiationError(error_msg)

    # committee_name = release.committee.name
    # committee_display = release.committee.display_name
    # project_name = release.project.name if release.project else "Unknown"
    # version = release.version

    subject = args.subject
    body = args.body

    # Perform substitutions in the body
    body = body.replace("[DURATION]", str(args.vote_duration))
    body = body.replace("[KEY_FINGERPRINT]", args.gpg_key_fingerprint or "(No key found)")
    body = body.replace("[YOUR_NAME]", args.initiator_id)

    # Set to a debugging recipient if the initiator is not sending to themselves
    original_recipient = args.email_to
    if original_recipient == f"{args.initiator_id}@apache.org":
        tooling_test_recipient = original_recipient
    else:
        # Send to a tooling test mailing list
        tooling_test_recipient = tooling_test_recipients[0] + "@tooling.apache.org"
        _LOGGER.info(f"TEMPORARY: Overriding recipient from {original_recipient} to {tooling_test_recipient}")

    # Create mail event
    event = mail.VoteEvent(
        release_name=args.release_name,
        email_sender=f"{args.initiator_id}@apache.org",
        email_recipient=tooling_test_recipient,
        subject=subject,
        body=body,
        vote_end=vote_end,
    )

    # Send the email
    mid = await mail.send(event)
    _LOGGER.info(
        f"Vote email sent successfully to test account {tooling_test_recipient} (would have been {original_recipient})"
    )

    return {
        "message": "Vote initiated successfully, and sent to test account",
        "original_email_to": original_recipient,
        "actual_email_to": tooling_test_recipient,
        "vote_end": vote_end_str,
        "subject": subject,
        "mid": mid,
    }
