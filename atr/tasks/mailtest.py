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

import logging
import os
from dataclasses import dataclass
from typing import Any

# Configure detailed logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create file handler for test.log
file_handler = logging.FileHandler("tasks-mailtest.log")
file_handler.setLevel(logging.DEBUG)

# Create formatter with detailed information
formatter = logging.Formatter(
    "[%(asctime)s.%(msecs)03d] [%(process)d] [%(levelname)s] [%(name)s:%(funcName)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
# Ensure parent loggers don't duplicate messages
logger.propagate = False

logger.info("Mail test module imported")


@dataclass
class Args:
    artifact_name: str
    email_recipient: str
    token: str

    @staticmethod
    def from_list(args: list[str]) -> "Args":
        """Parse command line arguments."""
        logger.debug(f"Parsing arguments: {args}")

        if len(args) != 3:
            logger.error(f"Invalid number of arguments: {len(args)}, expected 3")
            raise ValueError("Invalid number of arguments")

        artifact_name = args[0]
        email_recipient = args[1]
        token = args[2]

        if not isinstance(artifact_name, str):
            logger.error(f"Artifact name must be a string, got {type(artifact_name)}")
            raise ValueError("Artifact name must be a string")
        if not isinstance(email_recipient, str):
            logger.error(f"Email recipient must be a string, got {type(email_recipient)}")
            raise ValueError("Email recipient must be a string")
        if not isinstance(token, str):
            logger.error(f"Token must be a string, got {type(token)}")
            raise ValueError("Token must be a string")
        logger.debug("All argument validations passed")

        args_obj = Args(
            artifact_name=artifact_name,
            email_recipient=email_recipient,
            token=token,
        )

        logger.info(f"Args object created: {args_obj}")
        return args_obj


def send(args: list[str]) -> tuple[str, str | None, tuple[Any, ...]]:
    """Send a test email."""
    logger.info(f"Sending with args: {args}")
    try:
        logger.debug("Delegating to send_core function")
        status, error, result = send_core(args)
        logger.info(f"Send completed with status: {status}")
        return status, error, result
    except Exception as e:
        logger.exception(f"Error in send function: {e}")
        return "FAILED", str(e), tuple()


def send_core(args_list: list[str]) -> tuple[str, str | None, tuple[Any, ...]]:
    """Send a test email."""
    import atr.mail

    logger.info("Starting send_core")
    try:
        # Configure root logger to also write to our log file
        # This ensures logs from mail.py, using the root logger, are captured
        root_logger = logging.getLogger()
        # Check whether our file handler is already added, to avoid duplicates
        has_our_handler = any(
            (isinstance(h, logging.FileHandler) and h.baseFilename.endswith("tasks-mailtest.log"))
            for h in root_logger.handlers
        )
        if not has_our_handler:
            # Add our file handler to the root logger
            root_logger.addHandler(file_handler)
            logger.info("Added file handler to root logger to capture mail.py logs")

        logger.debug(f"Parsing arguments: {args_list}")
        args = Args.from_list(args_list)
        logger.info(
            f"Args parsed successfully: artifact_name={args.artifact_name}, email_recipient={args.email_recipient}"
        )

        # Load and set DKIM key
        try:
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            dkim_path = os.path.join(project_root, "state", "dkim.private")

            with open(dkim_path) as f:
                dkim_key = f.read()
                atr.mail.set_secret_key(dkim_key.strip())
                logger.info("DKIM key loaded and set successfully")
        except Exception as e:
            error_msg = f"Failed to load DKIM key: {e}"
            logger.error(error_msg)
            return "FAILED", error_msg, tuple()

        event = atr.mail.ArtifactEvent(
            artifact_name=args.artifact_name,
            email_recipient=args.email_recipient,
            token=args.token,
        )
        atr.mail.send(event)
        logger.info(f"Email sent successfully to {args.email_recipient}")

        return "COMPLETED", None, tuple()

    except Exception as e:
        logger.exception(f"Error in send_core: {e}")
        return "FAILED", str(e), tuple()
