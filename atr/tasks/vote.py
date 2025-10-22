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

import atr.construct as construct
import atr.db as db
import atr.db.interaction as interaction
import atr.log as log
import atr.mail as mail
import atr.models.results as results
import atr.models.schema as schema
import atr.tasks.checks as checks
import atr.util as util


class Initiate(schema.Strict):
    """Arguments for the task to start a vote."""

    release_name: str = schema.description("The name of the release to vote on")
    email_to: str = schema.description("The mailing list address to send the vote email to")
    vote_duration: int = schema.description("Duration of the vote in hours")
    initiator_id: str = schema.description("ASF ID of the vote initiator")
    initiator_fullname: str = schema.description("Full name of the vote initiator")
    subject: str = schema.description("Subject line for the vote email")
    body: str = schema.description("Body content for the vote email")


class VoteInitiationError(Exception): ...


@checks.with_model(Initiate)
async def initiate(args: Initiate) -> results.Results | None:
    """Initiate a vote for a release."""
    try:
        return await _initiate_core_logic(args)

    except VoteInitiationError as e:
        log.error(f"Vote initiation failed: {e}")
        raise
    except Exception as e:
        log.exception(f"Unexpected error during vote initiation: {e}")
        raise


async def _initiate_core_logic(args: Initiate) -> results.Results | None:
    """Get arguments, create an email, and then send it to the recipient."""
    log.info("Starting initiate_core")

    # Validate arguments
    if not (args.email_to.endswith("@apache.org") or args.email_to.endswith(".apache.org")):
        log.error(f"Invalid destination email address: {args.email_to}")
        raise VoteInitiationError("Invalid destination email address")

    async with db.session() as data:
        release = await data.release(name=args.release_name, _project=True, _committee=True).demand(
            VoteInitiationError(f"Release {args.release_name} not found")
        )
        latest_revision_number = release.latest_revision_number
        if latest_revision_number is None:
            raise VoteInitiationError(f"No revisions found for release {args.release_name}")

        ongoing_tasks = await interaction.tasks_ongoing(release.project.name, release.version, latest_revision_number)
        if ongoing_tasks > 0:
            raise VoteInitiationError(f"Cannot start vote for {args.release_name} as {ongoing_tasks} are not complete")

    # Calculate vote end date
    vote_duration_hours = args.vote_duration
    vote_start = datetime.datetime.now(datetime.UTC)
    vote_end = vote_start + datetime.timedelta(hours=vote_duration_hours)

    # Format dates for email
    vote_end_str = vote_end.strftime("%Y-%m-%d %H:%M:%S UTC")

    # # Load and set DKIM key
    # try:
    #     await mail.set_secret_key_default()
    # except Exception as e:
    #     error_msg = f"Failed to load DKIM key: {e}"
    #     log.error(error_msg)
    #     raise VoteInitiationError(error_msg)

    # Get PMC and project details
    if release.committee is None:
        error_msg = "Release has no associated committee"
        log.error(error_msg)
        raise VoteInitiationError(error_msg)

    # Construct email
    subject = args.subject

    # Perform substitutions in the body
    body = await construct.start_vote_body(
        args.body,
        construct.StartVoteOptions(
            asfuid=args.initiator_id,
            fullname=args.initiator_fullname,
            project_name=release.project.name,
            version_name=release.version,
            vote_duration=args.vote_duration,
        ),
    )

    permitted_recipients = util.permitted_voting_recipients(args.initiator_id, release.committee.name)
    if args.email_to not in permitted_recipients:
        log.error(f"Invalid mailing list choice: {args.email_to} not in {permitted_recipients}")
        raise VoteInitiationError("Invalid mailing list choice")

    # Create mail message
    log.info(f"Creating mail message for {args.email_to}")
    message = mail.Message(
        email_sender=f"{args.initiator_id}@apache.org",
        email_recipient=args.email_to,
        subject=subject,
        body=body,
    )

    # Send the email
    mid, mail_errors = await mail.send(message)

    # Original success message structure
    result = results.VoteInitiate(
        kind="vote_initiate",
        message="Vote announcement email sent successfully",
        email_to=args.email_to,
        vote_end=vote_end_str,
        subject=subject,
        mid=mid,
        mail_send_warnings=mail_errors,
    )

    if mail_errors:
        log.warning(f"Start vote for {args.release_name}: sending to {args.email_to}  gave errors: {mail_errors}")
    else:
        log.info(f"Vote email sent successfully to {args.email_to}")
    return result
