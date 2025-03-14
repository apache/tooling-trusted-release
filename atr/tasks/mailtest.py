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
import logging
import os
from typing import Any, Final

import atr.tasks.task as task

# Configure detailed logging
_LOGGER: Final = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)

# Create file handler for test.log
_HANDLER: Final = logging.FileHandler("tasks-mailtest.log")
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

_LOGGER.info("Mail test module imported")


# TODO: Use a Pydantic model instead
@dataclasses.dataclass
class Args:
    artifact_name: str
    email_recipient: str
    token: str

    @staticmethod
    def from_list(args: list[str]) -> "Args":
        """Parse command line arguments."""
        _LOGGER.debug(f"Parsing arguments: {args}")

        if len(args) != 3:
            _LOGGER.error(f"Invalid number of arguments: {len(args)}, expected 3")
            raise ValueError("Invalid number of arguments")

        artifact_name = args[0]
        email_recipient = args[1]
        token = args[2]

        if not isinstance(artifact_name, str):
            _LOGGER.error(f"Artifact name must be a string, got {type(artifact_name)}")
            raise ValueError("Artifact name must be a string")
        if not isinstance(email_recipient, str):
            _LOGGER.error(f"Email recipient must be a string, got {type(email_recipient)}")
            raise ValueError("Email recipient must be a string")
        if not isinstance(token, str):
            _LOGGER.error(f"Token must be a string, got {type(token)}")
            raise ValueError("Token must be a string")
        _LOGGER.debug("All argument validations passed")

        args_obj = Args(
            artifact_name=artifact_name,
            email_recipient=email_recipient,
            token=token,
        )

        _LOGGER.info(f"Args object created: {args_obj}")
        return args_obj


def send(args: list[str]) -> tuple[task.Status, str | None, tuple[Any, ...]]:
    """Send a test email."""
    _LOGGER.info(f"Sending with args: {args}")
    try:
        _LOGGER.debug("Delegating to send_core function")
        status, error, result = send_core(args)
        _LOGGER.info(f"Send completed with status: {status}")
        return status, error, result
    except Exception as e:
        _LOGGER.exception(f"Error in send function: {e}")
        return task.FAILED, str(e), tuple()


def send_core(args_list: list[str]) -> tuple[task.Status, str | None, tuple[Any, ...]]:
    """Send a test email."""
    import asyncio

    import atr.mail
    from atr.db.service import get_committee_by_name

    _LOGGER.info("Starting send_core")
    try:
        # Configure root _LOGGER to also write to our log file
        # This ensures logs from mail.py, using the root _LOGGER, are captured
        root_logger = logging.getLogger()
        # Check whether our file handler is already added, to avoid duplicates
        has_our_handler = any(
            (isinstance(h, logging.FileHandler) and h.baseFilename.endswith("tasks-mailtest.log"))
            for h in root_logger.handlers
        )
        if not has_our_handler:
            # Add our file handler to the root _LOGGER
            root_logger.addHandler(_HANDLER)
            _LOGGER.info("Added file handler to root _LOGGER to capture mail.py logs")

        _LOGGER.debug(f"Parsing arguments: {args_list}")
        args = Args.from_list(args_list)
        _LOGGER.info(
            f"Args parsed successfully: artifact_name={args.artifact_name}, email_recipient={args.email_recipient}"
        )

        # Check if the recipient is allowed
        # They must be a PMC member of tooling or dev@tooling.apache.org
        email_recipient = args.email_recipient
        local_part, domain = email_recipient.split("@", 1)

        # Allow dev@tooling.apache.org
        if email_recipient != "dev@tooling.apache.org":
            # Must be a PMC member of tooling
            # Since get_pmc_by_name is async, we need to run it in an event loop
            # TODO: We could make a sync version
            tooling_committee = asyncio.run(get_committee_by_name("tooling"))

            if not tooling_committee:
                error_msg = "Tooling committee not found in database"
                _LOGGER.error(error_msg)
                return task.FAILED, error_msg, tuple()

            if domain != "apache.org":
                error_msg = f"Email domain must be apache.org, got {domain}"
                _LOGGER.error(error_msg)
                return task.FAILED, error_msg, tuple()

            if local_part not in tooling_committee.committee_members:
                error_msg = f"Email recipient {local_part} is not a member of the tooling committee"
                _LOGGER.error(error_msg)
                return task.FAILED, error_msg, tuple()

            _LOGGER.info(f"Recipient {email_recipient} is a tooling committee member, allowed")

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

        event = atr.mail.ArtifactEvent(
            artifact_name=args.artifact_name,
            email_recipient=args.email_recipient,
            token=args.token,
        )
        atr.mail.send(event)
        _LOGGER.info(f"Email sent successfully to {args.email_recipient}")

        return task.COMPLETED, None, tuple()

    except Exception as e:
        _LOGGER.exception(f"Error in send_core: {e}")
        return task.FAILED, str(e), tuple()
