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

import asyncio
import datetime
import email.utils as utils
import io
import logging
import smtplib
import time
import uuid

import aiosmtplib
import dkim
import dns.rdtypes.ANY.MX as MX
import dns.resolver as resolver

_LOGGER = logging.getLogger(__name__)

# TODO: We should choose a pattern for globals
# We could e.g. use uppercase instead of global_
# It's not always worth identifying globals as globals
# But in many cases we should do so
# TODO: Get at least global_domain from configuration
# And probably global_dkim_selector too
global_dkim_selector: str = "202501"
global_domain: str = "tooling-vm-ec2-de.apache.org"
global_email_contact: str = f"contact@{global_domain}"
global_secret_key: str | None = None


class VoteEvent:
    """Data class to represent a release vote event."""

    def __init__(
        self, release_name: str, email_recipient: str, subject: str, body: str, vote_end: datetime.datetime
    ) -> None:
        self.release_name = release_name
        self.email_recipient = email_recipient
        self.subject = subject
        self.body = body
        self.vote_end = vote_end


async def send(event: VoteEvent) -> None:
    """Send an email notification about an artifact or a vote."""
    _LOGGER.info(f"Sending email for event: {event}")
    from_addr = global_email_contact
    to_addr = event.email_recipient
    _validate_recipient(to_addr)

    # UUID4 is entirely random, with no timestamp nor namespace
    # It does have 6 version and variant bits, so only 122 bits are random
    mid = f"<{uuid.uuid4()}@{global_domain}>"

    # Different message format depending on event type
    msg_text = f"""
From: {from_addr}
To: {to_addr}
Subject: {event.subject}
Date: {utils.formatdate(localtime=True)}
Message-ID: {mid}

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


def set_secret_key(key: str) -> None:
    """Set the secret key for DKIM signing."""
    global global_secret_key
    global_secret_key = key


async def _resolve_mx_records(domain: str) -> list[tuple[str, int]]:
    """Resolve MX records."""
    try:
        mx_records = await asyncio.to_thread(resolver.resolve, domain, "MX")
        mxs = []

        for rdata in mx_records:
            if not isinstance(rdata, MX.MX):
                raise ValueError(f"Unexpected MX record type: {type(rdata)}")
            mx = rdata
            mxs.append((mx.exchange.to_text(True), mx.preference))
        # Sort by preference
        mxs.sort(key=lambda x: x[1])

        if not mxs:
            mxs = [(domain, 0)]
    except Exception as e:
        raise ValueError(f"Failed to lookup MX records for {domain}: {e}")
    return mxs


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
        domain=bytes(global_domain, "utf-8"),
        privkey=private_key,
        include_headers=[b"From", b"To", b"Subject", b"Date", b"Message-ID"],
    )

    # Prepend the DKIM signature to the message
    dkim_msg = sig + message_bytes
    dkim_reader = io.StringIO(str(dkim_msg, "utf-8"))

    _LOGGER.info("email_send_many")

    for addr in to_addrs:
        _, domain = _split_address(addr)

        if domain == "localhost":
            mxs = [("127.0.0.1", 0)]
        else:
            mxs = await _resolve_mx_records(domain)

        # Try each MX server
        errors = []
        for mx_host, _ in mxs:
            try:
                await _send_one(mx_host, from_addr, addr, dkim_reader)
                # Success, no need to try other MX servers
                break
            except Exception as e:
                errors.append(f"Failed to send to {mx_host}: {e}")
                # Reset reader for next attempt
                dkim_reader.seek(0)
        else:
            # If we get here, all MX servers failed
            raise Exception("; ".join(errors))


async def _send_one(mx_host: str, from_addr: str, to_addr: str, msg_reader: io.StringIO) -> None:
    """Send an email to a single recipient via the ASF mail relay."""
    default_timeout_seconds = 30
    _validate_recipient(to_addr)

    try:
        # Connect to the ASF mail relay
        # TODO: Use asfpy for sending mail
        mail_relay = "mail-relay.apache.org"
        _LOGGER.info(f"Connecting async to {mail_relay}:587")
        smtp = aiosmtplib.SMTP(hostname=mail_relay, port=587, timeout=default_timeout_seconds)
        await smtp.connect()
        _LOGGER.info(f"Connected to {smtp.hostname}:{smtp.port}")

        # Identify ourselves to the server
        await smtp.ehlo()

        # # Use STARTTLS for port 587
        # context = ssl.create_default_context()
        # context.minimum_version = ssl.TLSVersion.TLSv1_2
        # await smtp.starttls(tls_context=context)
        await smtp.ehlo()

        # Send the message
        await smtp.sendmail(from_addr, [to_addr], msg_reader.read())

        # Close the connection
        await smtp.quit()

    except (OSError, smtplib.SMTPException) as e:
        # TODO: Check whether aiosmtplib raises different exceptions
        _LOGGER.error(f"Async SMTP error: {e}")
        raise Exception(f"SMTP error: {e}")


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
