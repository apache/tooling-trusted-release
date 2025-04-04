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
import email.utils as utils
import logging
import ssl
import time
import uuid
from typing import Final

import aiosmtplib
import dkim

_LOGGER = logging.getLogger(__name__)

# TODO: We should choose a pattern for globals
# We could e.g. use uppercase instead of global_
# It's not always worth identifying globals as globals
# But in many cases we should do so
# TODO: Get at least global_dkim_domain from configuration
# And probably global_dkim_selector too
global_dkim_selector: str = "mail"
global_dkim_domain: str = "apache.org"
global_secret_key: str | None = None

_MAIL_RELAY: Final[str] = "mail-relay.apache.org"
_SMTP_PORT: Final[int] = 587
_SMTP_TIMEOUT: Final[int] = 30


@dataclasses.dataclass
class VoteEvent:
    release_name: str
    email_sender: str
    email_recipient: str
    subject: str
    body: str
    vote_end: datetime.datetime


async def send(event: VoteEvent) -> str:
    """Send an email notification about an artifact or a vote."""
    _LOGGER.info(f"Sending email for event: {event}")
    from_addr = event.email_sender
    if not from_addr.endswith(f"@{global_dkim_domain}"):
        raise ValueError(f"from_addr must end with @{global_dkim_domain}, got {from_addr}")
    to_addr = event.email_recipient
    _validate_recipient(to_addr)

    # UUID4 is entirely random, with no timestamp nor namespace
    # It does have 6 version and variant bits, so only 122 bits are random
    mid = f"{uuid.uuid4()}@{global_dkim_domain}"
    msg_text = f"""
From: {from_addr}
To: {to_addr}
Subject: {event.subject}
Date: {utils.formatdate(localtime=True)}
Message-ID: <{mid}>

{event.body}
"""

    # Convert Unix line endings to CRLF
    msg_text = msg_text.strip().replace("\n", "\r\n") + "\r\n"

    start = time.perf_counter()
    _LOGGER.info(f"sending message: {msg_text}")

    try:
        await _send_many(from_addr, [to_addr], msg_text)
    except Exception as e:
        _LOGGER.error(f"send error: {e}")
        raise e
    else:
        _LOGGER.info(f"sent to {to_addr}")

    elapsed = time.perf_counter() - start
    _LOGGER.info(f" send_many took {elapsed:.3f}s")

    return mid


def set_secret_key(key: str) -> None:
    """Set the secret key for DKIM signing."""
    global global_secret_key
    global_secret_key = key


async def _send_many(from_addr: str, to_addrs: list[str], msg_text: str) -> None:
    """Send an email to multiple recipients with DKIM signing."""
    message_bytes = bytes(msg_text, "utf-8")

    if global_secret_key is None:
        raise ValueError("global_secret_key is not set")

    # DKIM sign the message
    private_key = bytes(global_secret_key, "utf-8")

    # Create a DKIM signature
    sig = dkim.sign(
        message=message_bytes,
        selector=bytes(global_dkim_selector, "utf-8"),
        domain=bytes(global_dkim_domain, "utf-8"),
        privkey=private_key,
        include_headers=[b"From", b"To", b"Subject", b"Date", b"Message-ID"],
    )

    # Prepend the DKIM signature to the message
    dkim_msg = sig + message_bytes

    _LOGGER.info("email_send_many")

    errors = []
    for addr in to_addrs:
        try:
            await _send_via_relay(from_addr, addr, dkim_msg)
        except Exception as e:
            _LOGGER.exception(f"Failed to send to {addr}:")
            errors.append(f"failed to send to {addr}: {e}")

    if errors:
        # Raising an exception will ensure that any calling task is marked as failed
        raise Exception("Failed to send to one or more recipients: " + "; ".join(errors))


async def _send_via_relay(from_addr: str, to_addr: str, dkim_msg_bytes: bytes) -> None:
    """Send a DKIM signed email to a single recipient via the ASF mail relay."""
    _validate_recipient(to_addr)

    # Connect to the ASF mail relay
    # NOTE: Our code is very different from the asfpy code:
    # - Uses types
    # - Uses asyncio
    # - Performs DKIM signing
    # Due to the divergence, we should probably not contribute upstream
    # In effect, these are two different "packages" of functionality
    # We can't even sign it first and pass it to asfpy, due to its different design
    _LOGGER.info(f"Connecting async to {_MAIL_RELAY}:{_SMTP_PORT}")
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    smtp = aiosmtplib.SMTP(hostname=_MAIL_RELAY, port=_SMTP_PORT, timeout=_SMTP_TIMEOUT, tls_context=context)
    await smtp.connect()
    _LOGGER.info(f"Connected to {smtp.hostname}:{smtp.port}")
    await smtp.ehlo()
    await smtp.sendmail(from_addr, [to_addr], dkim_msg_bytes)
    await smtp.quit()


def _split_address(addr: str) -> tuple[str, str]:
    """Split an email address into local and domain parts."""
    parts = addr.split("@", 1)
    if len(parts) != 2:
        raise ValueError("Invalid mail address")
    return parts[0], parts[1]


def _validate_recipient(to_addr: str) -> None:
    # Ensure recipient is @apache.org or @tooling.apache.org
    _, domain = _split_address(to_addr)
    if domain not in ("apache.org", "tooling.apache.org"):
        error_msg = f"Email recipient must be @apache.org or @tooling.apache.org, got {to_addr}"
        _LOGGER.error(error_msg)
        raise ValueError(error_msg)
