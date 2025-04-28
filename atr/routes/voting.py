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

import asfquart.base as base
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.routes.compose as compose
import atr.routes.resolve as resolve
import atr.routes.root as root
import atr.tasks.vote as tasks_vote
import atr.user as user
import atr.util as util


@routes.committer("/voting/<project_name>/<version_name>/<revision>", methods=["GET", "POST"])
async def selected_revision(
    session: routes.CommitterSession, project_name: str, version_name: str, revision: str
) -> response.Response | str:
    """Show the vote initiation form for a release."""
    await session.check_access(project_name)

    async with db.session() as data:
        project = await data.project(name=project_name).demand(routes.FlashError("Project not found"))
        release = await data.release(project_name=project.name, version=version_name, _committee=True).demand(
            routes.FlashError("Release candidate not found")
        )
        # Check that the user is on the project committee for the release
        # TODO: Consider relaxing this to all committers
        # Otherwise we must not show the vote form
        if not user.is_committee_member(release.committee, session.uid):
            return await session.redirect(
                compose.selected, error="You must be on the PMC of this project to start a vote"
            )
        committee = util.unwrap(release.committee)

        sender = f"{session.uid}@apache.org"
        permitted_recipients = util.permitted_vote_recipients(session.uid)

        if release.vote_policy:
            min_hours = release.vote_policy.min_hours
        else:
            min_hours = 72

        class VoteInitiateForm(util.QuartFormTyped):
            """Form for initiating a release vote."""

            release_name = wtforms.HiddenField("Release Name")
            mailing_list = wtforms.RadioField(
                "Send vote email to",
                choices=[
                    (recipient, recipient) if (recipient != sender) else (recipient, f"{recipient} (preview only)")
                    for recipient in permitted_recipients
                ],
                validators=[wtforms.validators.InputRequired("Mailing list selection is required")],
                default="user-tests@tooling.apache.org",
            )
            vote_duration = wtforms.IntegerField(
                "Minimum vote duration in hours",
                validators=[
                    wtforms.validators.InputRequired("Vote duration is required"),
                    util.validate_vote_duration,
                ],
                default=min_hours,
            )
            subject = wtforms.StringField("Subject", validators=[wtforms.validators.Optional()])
            body = wtforms.TextAreaField("Body", validators=[wtforms.validators.Optional()])
            submit = wtforms.SubmitField("Send vote email")

        version = release.version
        committee_name = committee.name
        committee_display = committee.display_name
        project_name = release.project.name if release.project else "Unknown"

        default_subject = f"[VOTE] Release Apache {committee_display} {project_name} {version}"
        default_body = f"""Hello {committee_name},

I'd like to call a vote on releasing the following artifacts as
Apache {committee_display} {project_name} {version}.

The release candidate can be found at:

https://apache.example.org/{committee_name}/{project_name}-{version}/

The release artifacts are signed with the GPG key with fingerprint:

  [KEY_FINGERPRINT]

Please review the release candidate and vote accordingly.

[ ] +1 Release this package
[ ] +0 Abstain
[ ] -1 Do not release this package (please provide specific comments)

This vote will remain open for [DURATION] hours.

Thanks,
[YOUR_NAME]
"""

        form = await VoteInitiateForm.create_form(
            data=await quart.request.form if quart.request.method == "POST" else None,
        )
        # Set hidden field data explicitly
        form.release_name.data = release.name

        if quart.request.method == "GET":
            form.subject.data = default_subject
            form.body.data = default_body

        if await form.validate_on_submit():
            email_to: str = util.unwrap(form.mailing_list.data)
            vote_duration_choice: int = util.unwrap(form.vote_duration.data)
            subject_data: str = util.unwrap(form.subject.data)
            body_data: str = util.unwrap(form.body.data)

            if committee is None:
                raise base.ASFQuartException("Release has no associated committee", errorcode=400)

            if email_to not in permitted_recipients:
                # This will be checked again by tasks/vote.py for extra safety
                raise base.ASFQuartException("Invalid mailing list choice", errorcode=400)
            if email_to != sender:
                error = await _promote(data, release.name)
                if error:
                    return await session.redirect(root.index, error=error)

                # This is now handled by the _promote call, above
                # # Update the release phase to the voting phase only if not sending a test message to the user
                # release.phase = models.ReleasePhase.RELEASE_CANDIDATE

                # Store when the release was put into the voting phase
                release.vote_started = datetime.datetime.now(datetime.UTC)

                # TODO: We also need to store the duration of the vote
                # We can't allow resolution of the vote until the duration has elapsed
                # But we allow the user to specify in the form
                # And yet we also have VotePolicy.min_hours
                # Presumably this sets the default, and the form takes precedence?
                # VotePolicy.min_hours can also be 0, though

            # Create a task for vote initiation
            task = models.Task(
                status=models.TaskStatus.QUEUED,
                task_type=models.TaskType.VOTE_INITIATE,
                task_args=tasks_vote.Initiate(
                    release_name=release.name,
                    email_to=email_to,
                    vote_duration=vote_duration_choice,
                    initiator_id=session.uid,
                    subject=subject_data,
                    body=body_data,
                ).model_dump(),
                release_name=release.name,
            )

            data.add(task)
            # Flush to get the task ID
            await data.flush()
            await data.commit()

            # NOTE: During debugging, this email is actually sent elsewhere
            # TODO: We should perhaps move that logic here, so that we can show the debugging address
            # We should also log all outgoing email and the session so that users can confirm
            # And can be warned if there was a failure
            # (The message should be shown on the vote resolution page)
            # TODO: Link to the vote resolution page in the flash message
            if email_to == sender:
                # Test email, with no promotion
                return await session.redirect(
                    compose.selected,
                    success=f"The vote announcement email will soon be sent to {email_to}. "
                    "This is a test, and the release is not being voted on.",
                    project_name=project_name,
                    version_name=version,
                )

            return await session.redirect(
                resolve.selected,
                success=f"The vote announcement email will soon be sent to {email_to}.",
                project_name=project_name,
                version_name=version,
            )

        # For GET requests or failed POST validation
        return await quart.render_template(
            "voting-selected-revision.html",
            release=release,
            form=form,
            revision=revision,
        )


async def _promote(
    data: db.Session,
    release_name: str,
) -> str | None:
    """Promote a release candidate draft to a new phase."""
    # Get the release
    # TODO: Use session.release here
    release = await data.release(name=release_name, _project=True).demand(
        routes.FlashError("Release candidate draft not found")
    )

    # Verify that it's in the correct phase
    if release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
        return "This release is not in the candidate draft phase"

    # Count how many files are in the source directory
    file_count = await util.number_of_release_files(release)
    if file_count == 0:
        return "This candidate draft is empty, containing no files"

    # Promote it to the target phase
    # TODO: Obtain a lock for this
    # NOTE: The functionality for skipping phases has been removed
    release.stage = models.ReleaseStage.RELEASE_CANDIDATE
    release.phase = models.ReleasePhase.RELEASE_CANDIDATE

    # We updated the release
    await data.commit()

    return None
