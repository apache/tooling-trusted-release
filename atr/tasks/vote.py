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

import dataclasses
import datetime
import logging
import os
from typing import Any, Final

import atr.db.models as models
import atr.tasks.task as task

# Configure detailed logging
_LOGGER: Final = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)

# Create file handler for tasks-vote.log
_HANDLER: Final = logging.FileHandler("tasks-vote.log")
_HANDLER.setLevel(logging.DEBUG)

# Create formatter with detailed information
_HANDLER.setFormatter(
    logging.Formatter(
        "[%(asctime)s.%(msecs)03d] [%(process)d] [%(levelname)s] [%(name)s:%(funcName)s:%(lineno)d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)
_LOGGER.addHandler(_HANDLER)
# Ensure parent loggers don't duplicate messages
_LOGGER.propagate = False

_LOGGER.info("Vote module imported")


@dataclasses.dataclass
class Args:
    """Arguments for the vote_initiate task."""

    release_name: str
    email_to: str
    vote_duration: str
    gpg_key_id: str
    commit_hash: str
    initiator_id: str

    @staticmethod
    def from_list(args: list[str]) -> "Args":
        """Parse task arguments."""
        _LOGGER.debug(f"Parsing arguments: {args}")

        if len(args) != 6:
            _LOGGER.error(f"Invalid number of arguments: {len(args)}, expected 6")
            raise ValueError("Invalid number of arguments")

        release_name = args[0]
        email_to = args[1]
        vote_duration = args[2]
        gpg_key_id = args[3]
        commit_hash = args[4]
        initiator_id = args[5]

        # Type checking
        for arg_name, arg_value in [
            ("release_name", release_name),
            ("email_to", email_to),
            ("vote_duration", vote_duration),
            ("gpg_key_id", gpg_key_id),
            ("commit_hash", commit_hash),
            ("initiator_id", initiator_id),
        ]:
            if not isinstance(arg_value, str):
                _LOGGER.error(f"{arg_name} must be a string, got {type(arg_value)}")
                raise ValueError(f"{arg_name} must be a string")

        _LOGGER.debug("All argument validations passed")

        args_obj = Args(
            release_name=release_name,
            email_to=email_to,
            vote_duration=vote_duration,
            gpg_key_id=gpg_key_id,
            commit_hash=commit_hash,
            initiator_id=initiator_id,
        )

        _LOGGER.info(f"Args object created: {args_obj}")
        return args_obj


def initiate(args: list[str]) -> tuple[models.TaskStatus, str | None, tuple[Any, ...]]:
    """Initiate a vote for a release."""
    _LOGGER.info(f"Initiating vote with args: {args}")
    try:
        _LOGGER.debug("Delegating to initiate_core function")
        status, error, result = initiate_core(args)
        _LOGGER.info(f"Vote initiation completed with status: {status}")
        return status, error, result
    except Exception as e:
        _LOGGER.exception(f"Error in initiate function: {e}")
        return task.FAILED, str(e), tuple()


def initiate_core(args_list: list[str]) -> tuple[models.TaskStatus, str | None, tuple[Any, ...]]:
    """Get arguments, create an email, and then send it to the recipient."""
    import atr.db.service as service
    import atr.mail

    test_recipients = ["sbp"]
    _LOGGER.info("Starting initiate_core")
    try:
        # Configure root _LOGGER to also write to our log file
        # This ensures logs from mail.py, using the root _LOGGER, are captured
        root_logger = logging.getLogger()
        # Check whether our file handler is already added, to avoid duplicates
        has_our_handler = any(
            (isinstance(h, logging.FileHandler) and h.baseFilename.endswith("tasks-vote.log"))
            for h in root_logger.handlers
        )
        if not has_our_handler:
            # Add our file handler to the root _LOGGER
            root_logger.addHandler(_HANDLER)
            _LOGGER.info("Added file handler to root _LOGGER to capture mail.py logs")

        _LOGGER.debug(f"Parsing arguments: {args_list}")
        args = Args.from_list(args_list)
        _LOGGER.info(f"Args parsed successfully: {args}")

        # Get the release information
        release = service.get_release_by_name_sync(args.release_name)
        if not release:
            error_msg = f"Release with key {args.release_name} not found"
            _LOGGER.error(error_msg)
            return task.FAILED, error_msg, tuple()

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

            with open(dkim_path) as f:
                dkim_key = f.read()
                atr.mail.set_secret_key(dkim_key.strip())
                _LOGGER.info("DKIM key loaded and set successfully")
        except Exception as e:
            error_msg = f"Failed to load DKIM key: {e}"
            _LOGGER.error(error_msg)
            return task.FAILED, error_msg, tuple()

        # Get PMC and project details
        if release.committee is None:
            error_msg = "Release has no associated committee"
            _LOGGER.error(error_msg)
            return task.FAILED, error_msg, tuple()

        committee_name = release.committee.name
        committee_display = release.committee.display_name
        project_name = release.project.name if release.project else "Unknown"
        version = release.version

        # Create email subject
        subject = f"[VOTE] Release Apache {committee_display} {project_name} {version}"

        # Create email body with initiator ID
        body = f"""Hello {committee_name},

I'd like to call a vote on releasing the following artifacts as
Apache {committee_display} {project_name} {version}.

The release candidate can be found at:

https://apache.example.org/{committee_name}/{project_name}-{version}/

The release artifacts are signed with my GPG key, {gpg_key_id}.

The artifacts were built from commit:

{args.commit_hash}

Please review the release candidate and vote accordingly.

[ ] +1 Release this package
[ ] +0 Abstain
[ ] -1 Do not release this package (please provide specific comments)

This vote will remain open until {vote_end_str} ({vote_duration_hours} hours).

Thanks,
{args.initiator_id}
"""

        # Store the original recipient for logging
        original_recipient = args.email_to
        # Only one test recipient is required for now
        test_recipient = test_recipients[0] + "@apache.org"
        _LOGGER.info(f"TEMPORARY: Overriding recipient from {original_recipient} to {test_recipient}")

        # Create mail event with test recipient
        # Use test account instead of actual PMC list
        event = atr.mail.VoteEvent(
            release_name=args.release_name,
            email_recipient=test_recipient,
            subject=subject,
            body=body,
            vote_end=vote_end,
        )

        # Send the email
        atr.mail.send(event)
        _LOGGER.info(
            f"Vote email sent successfully to test account {test_recipient} (would have been {original_recipient})"
        )

        # TODO: Update release status to indicate a vote is in progress
        # This would involve updating the database with the vote details somehow
        return (
            task.COMPLETED,
            None,
            (
                {
                    "message": "Vote initiated successfully (sent to test account)",
                    "original_email_to": original_recipient,
                    "actual_email_to": test_recipient,
                    "vote_end": vote_end_str,
                    "subject": subject,
                },
            ),
        )

    except Exception as e:
        _LOGGER.exception(f"Error in initiate_core: {e}")
        return task.FAILED, str(e), tuple()
