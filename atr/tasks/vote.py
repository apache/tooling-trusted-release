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


class VoteInitiationError(Exception): ...


class Initiate(pydantic.BaseModel):
    """Arguments for the task to start a vote."""

    release_name: str = pydantic.Field(..., description="The name of the release to vote on")
    email_to: str = pydantic.Field(..., description="The mailing list address to send the vote email to")
    vote_duration: str = pydantic.Field(..., description="Duration of the vote in hours, as a string")
    gpg_key_id: str = pydantic.Field(..., description="GPG Key ID of the initiator")
    commit_hash: str = pydantic.Field(..., description="Commit hash the artifacts were built from")
    initiator_id: str = pydantic.Field(..., description="ASF ID of the vote initiator")
    subject: str = pydantic.Field(..., description="Subject line for the vote email")
    body: str = pydantic.Field(..., description="Body content for the vote email")


@checks.with_model(Initiate)
async def initiate(args: Initiate) -> str | None:
    """Initiate a vote for a release."""
    try:
        result_data = await _initiate_core_logic(args)
        success_message = result_data.get("message", "Vote initiated successfully, but message missing")
        if not isinstance(success_message, str):
            raise VoteInitiationError("Success message is not a string")
        return success_message

    except VoteInitiationError as e:
        _LOGGER.error(f"Vote initiation failed: {e}")
        raise
    except Exception as e:
        _LOGGER.exception(f"Unexpected error during vote initiation: {e}")
        raise


async def _initiate_core_logic(args: Initiate) -> dict[str, Any]:
    """Get arguments, create an email, and then send it to the recipient."""
    test_recipients = ["sbp"]
    _LOGGER.info("Starting initiate_core")

    async with db.session() as data:
        release = await data.release(name=args.release_name, _project=True, _committee=True).demand(
            VoteInitiationError(f"Release {args.release_name} not found")
        )

    # GPG key ID, just for testing the UI
    gpg_key_id = args.gpg_key_id

    # Calculate vote end date
    vote_duration_hours = int(args.vote_duration)
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
    body = body.replace("[KEY_ID]", gpg_key_id or "(Not provided)")
    body = body.replace("[COMMIT_HASH]", args.commit_hash or "(Not provided)")
    body = body.replace("[DURATION]", args.vote_duration)
    body = body.replace("[YOUR_NAME]", args.initiator_id)

    # Store the original recipient for logging
    original_recipient = args.email_to
    # Only one test recipient is required for now
    test_recipient = test_recipients[0] + "@apache.org"
    _LOGGER.info(f"TEMPORARY: Overriding recipient from {original_recipient} to {test_recipient}")

    # Create mail event with test recipient
    # Use test account instead of actual PMC list
    event = mail.VoteEvent(
        release_name=args.release_name,
        email_recipient=test_recipient,
        subject=subject,
        body=body,
        vote_end=vote_end,
    )

    # Send the email
    await mail.send(event)
    _LOGGER.info(
        f"Vote email sent successfully to test account {test_recipient} (would have been {original_recipient})"
    )

    return {
        "message": "Vote initiated successfully (sent to test account)",
        "original_email_to": original_recipient,
        "actual_email_to": test_recipient,
        "vote_end": vote_end_str,
        "subject": subject,
    }
