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
from typing import Final

import atr.mail as mail
import atr.results as results
import atr.schema as schema
import atr.tasks.checks as checks
import atr.util as util

# Configure detailed logging
_LOGGER: Final = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)


class Send(schema.Strict):
    """Arguments for the task to send an email."""

    email_sender: str = schema.description("The email address of the sender")
    email_recipient: str = schema.description("The email address of the recipient")
    subject: str = schema.description("The subject of the email")
    body: str = schema.description("The body of the email")
    in_reply_to: str | None = schema.description("The message ID of the email to reply to")


class SendError(Exception): ...


@checks.with_model(Send)
async def send(args: Send) -> results.Results | None:
    if args.email_recipient not in util.permitted_recipients(args.email_sender):
        raise SendError(f"You are not permitted to send announcements to {args.email_recipient}")

    message = mail.Message(
        email_sender=args.email_sender,
        email_recipient=args.email_recipient,
        subject=args.subject,
        body=args.body,
        in_reply_to=args.in_reply_to,
    )

    # Send the email
    # TODO: Move this call into send itself?
    await mail.set_secret_key_default()
    mid, mail_errors = await mail.send(message)
    if mail_errors:
        _LOGGER.warning(f"Mail sending to {args.email_recipient} for subject '{args.subject}' encountered errors:")
        for error in mail_errors:
            _LOGGER.warning(f"- {error}")

    # TODO: Record the vote in the database?
    # We'd need to sync with manual votes too
    return results.MessageSend(
        kind="message_send",
        mid=mid,
        mail_send_warnings=mail_errors,
    )
