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
from typing import Any, Protocol

import aiofiles.os
import asfquart.base as base
import quart
import quart_wtf.typing as typing
import sqlmodel
import werkzeug.wrappers.response as response
import wtforms

import atr.construct as construct
import atr.db as db
import atr.db.interaction as interaction
import atr.forms as forms
import atr.models.sql as sql
import atr.routes as routes
import atr.routes.compose as compose
import atr.routes.root as root
import atr.routes.vote as vote
import atr.tasks.vote as tasks_vote
import atr.template as template
import atr.user as user
import atr.util as util


class VoteInitiateFormProtocol(Protocol):
    """Protocol for the dynamically generated VoteInitiateForm."""

    release_name: wtforms.HiddenField
    mailing_list: wtforms.RadioField
    vote_duration: wtforms.IntegerField
    subject: wtforms.StringField
    body: wtforms.TextAreaField
    submit: wtforms.SubmitField

    @property
    def errors(self) -> dict[str, Any]: ...

    async def validate_on_submit(self) -> bool: ...


@routes.committer("/voting/<project_name>/<version_name>/<revision>", methods=["GET", "POST"])
async def selected_revision(
    session: routes.CommitterSession, project_name: str, version_name: str, revision: str
) -> response.Response | str:
    """Show the vote initiation form for a release."""
    await session.check_access(project_name)

    async with db.session() as data:
        release = await session.release(
            project_name,
            version_name,
            data=data,
            with_project=True,
            with_committee=True,
            with_project_release_policy=True,
        )
        if release.project.policy_strict_checking:
            if await interaction.has_failing_checks(release, revision, caller_data=data):
                return await session.redirect(
                    compose.selected,
                    error="This release candidate draft has errors. Please fix the errors before starting a vote.",
                    project_name=project_name,
                    version_name=version_name,
                    revision=revision,
                )

        # Check that the user is on the project committee for the release
        # TODO: Consider relaxing this to all committers
        # Otherwise we must not show the vote form
        if not (user.is_committee_member(release.committee, session.uid) or user.is_admin(session.uid)):
            return await session.redirect(
                compose.selected,
                error="You must be on the PMC of this project to start a vote",
                project_name=project_name,
                version_name=version_name,
                revision=revision,
            )

        selected_revision_number = release.latest_revision_number
        if selected_revision_number is None:
            return await session.redirect(compose.selected, error="No revision found for this release")

        # committee = util.unwrap(release.committee)
        permitted_recipients = util.permitted_recipients(session.uid)
        if release.release_policy:
            min_hours = release.release_policy.min_hours if (release.release_policy.min_hours is not None) else 72
        else:
            min_hours = 72
        release_policy_mailto_addresses = ", ".join(release.project.policy_mailto_addresses)

        form_data = (await quart.request.form) if (quart.request.method == "POST") else None
        hidden_field = (form_data or {}).get("hidden_field")
        if isinstance(hidden_field, str):
            # This hidden_field is set to selected_revision_number
            # It's manual_vote_process_form.hidden_field.data in selected_revision
            selected_revision_number = hidden_field
            return await start_vote_manual(
                release,
                selected_revision_number,
                session,
                data,
            )

        form = await _form(
            release,
            form_data,
            project_name,
            version_name,
            permitted_recipients,
            release_policy_mailto_addresses,
            min_hours,
        )

        if await form.validate_on_submit():
            email_to: str = util.unwrap(form.mailing_list.data)
            vote_duration_choice: int = util.unwrap(form.vote_duration.data)
            subject_data: str = util.unwrap(form.subject.data)
            body_data: str = util.unwrap(form.body.data)
            return await start_vote(
                email_to,
                permitted_recipients,
                project_name,
                version_name,
                selected_revision_number,
                session,
                vote_duration_choice,
                subject_data,
                body_data,
                data,
                release,
                promote=True,
            )

    keys_warning = await _keys_warning(release)
    manual_vote_process_form = None
    if release.project.policy_manual_vote:
        manual_vote_process_form = await forms.Hidden.create_form()
        manual_vote_process_form.hidden_field.data = selected_revision_number
    has_files = await util.has_files(release)
    if not has_files:
        return await session.redirect(
            compose.selected,
            error="This release candidate draft has no files yet. Please add some files before starting a vote.",
            project_name=project_name,
            version_name=version_name,
        )

    # For GET requests or failed POST validation
    return await template.render(
        "voting-selected-revision.html",
        release=release,
        form=form,
        revision=revision,
        keys_warning=keys_warning,
        manual_vote_process_form=manual_vote_process_form,
    )


async def promote_release(
    data: db.Session,
    release_name: str,
    selected_revision_number: str,
    vote_manual: bool = False,
) -> str | None:
    """Promote a release candidate draft to a new phase."""
    # TODO: Use session.release here
    release_for_pre_checks = await data.release(name=release_name, _project=True).demand(
        routes.FlashError("Release candidate draft not found")
    )
    project_name = release_for_pre_checks.project.name
    version_name = release_for_pre_checks.version

    # Check for ongoing tasks
    ongoing_tasks = await interaction.tasks_ongoing(project_name, version_name, selected_revision_number)
    if ongoing_tasks > 0:
        return "All checks must be completed before starting a vote"

    # Verify that it's in the correct phase
    # The atomic update below will also check this
    if release_for_pre_checks.phase != sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
        return "This release is not in the candidate draft phase"

    # Check that the revision number is the latest
    if release_for_pre_checks.latest_revision_number != selected_revision_number:
        return "The selected revision number does not match the latest revision number"

    # Check that there is at least one file in the draft
    # This is why we require _project=True above
    file_count = await util.number_of_release_files(release_for_pre_checks)
    if file_count == 0:
        return "This candidate draft is empty, containing no files"

    # Promote it to RELEASE_CANDIDATE
    # NOTE: We previously allowed skipping phases, but removed that functionality
    # We don't need a lock here because we use an atomic update
    via = sql.validate_instrumented_attribute
    stmt = (
        sqlmodel.update(sql.Release)
        .where(
            via(sql.Release.name) == release_name,
            via(sql.Release.phase) == sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
            sql.latest_revision_number_query() == selected_revision_number,
        )
        .values(
            phase=sql.ReleasePhase.RELEASE_CANDIDATE,
            vote_started=datetime.datetime.now(datetime.UTC),
            vote_manual=vote_manual,
        )
    )

    result = await data.execute(stmt)
    if result.rowcount != 1:
        await data.rollback()
        return "A newer revision appeared, please refresh and try again."
    await data.commit()
    return None


async def start_vote(
    email_to: str,
    permitted_recipients: list[str],
    project_name: str,
    version_name: str,
    selected_revision_number: str,
    session: routes.CommitterSession,
    vote_duration_choice: int,
    subject_data: str,
    body_data: str,
    data: db.Session,
    release: sql.Release,
    promote: bool = True,
):
    if email_to not in permitted_recipients:
        # This will be checked again by tasks/vote.py for extra safety
        raise base.ASFQuartException("Invalid mailing list choice", errorcode=400)

    if promote is True:
        # This verifies the state and sets the phase to RELEASE_CANDIDATE
        error = await promote_release(data, release.name, selected_revision_number, vote_manual=False)
        if error:
            return await session.redirect(root.index, error=error)

    # TODO: We also need to store the duration of the vote
    # We can't allow resolution of the vote until the duration has elapsed
    # But we allow the user to specify in the form
    # And yet we also have ReleasePolicy.min_hours
    # Presumably this sets the default, and the form takes precedence?
    # ReleasePolicy.min_hours can also be 0, though

    # Create a task for vote initiation
    task = sql.Task(
        status=sql.TaskStatus.QUEUED,
        task_type=sql.TaskType.VOTE_INITIATE,
        task_args=tasks_vote.Initiate(
            release_name=release.name,
            email_to=email_to,
            vote_duration=vote_duration_choice,
            initiator_id=session.uid,
            initiator_fullname=session.fullname,
            subject=subject_data,
            body=body_data,
        ).model_dump(),
        asf_uid=util.unwrap(session.uid),
        project_name=project_name,
        version_name=version_name,
    )
    data.add(task)
    await data.commit()

    # TODO: We should log all outgoing email and the session so that users can confirm
    # And can be warned if there was a failure
    # (The message should be shown on the vote resolution page)
    return await session.redirect(
        vote.selected,
        success=f"The vote announcement email will soon be sent to {email_to}.",
        project_name=project_name,
        version_name=version_name,
    )


async def start_vote_manual(
    release: sql.Release,
    selected_revision_number: str,
    session: routes.CommitterSession,
    data: db.Session,
) -> response.Response | str:
    # This verifies the state and sets the phase to RELEASE_CANDIDATE
    error = await promote_release(data, release.name, selected_revision_number, vote_manual=True)
    if error:
        return await session.redirect(root.index, error=error)
    return await session.redirect(
        vote.selected,
        success="The manual vote process has been started.",
        project_name=release.project.name,
        version_name=release.version,
    )


async def _form(
    release: sql.Release,
    form_data: typing.FormData | None,
    project_name: str,
    version_name: str,
    permitted_recipients: list[str],
    release_policy_mailto_addresses: str,
    min_hours: int,
) -> VoteInitiateFormProtocol:
    class VoteInitiateForm(forms.Typed):
        """Form for initiating a release vote."""

        release_name = wtforms.HiddenField("Release Name")
        mailing_list = wtforms.RadioField(
            "Send vote email to",
            choices=sorted([(recipient, recipient) for recipient in permitted_recipients]),
            validators=[wtforms.validators.InputRequired("Mailing list selection is required")],
            default="user-tests@tooling.apache.org",
            description="NOTE: The limited options above are provided for testing purposes."
            " In the finished version of ATR, you will be able to send to your own specified mailing lists, i.e. "
            f"{release_policy_mailto_addresses}.",
        )
        vote_duration = wtforms.IntegerField(
            "Minimum vote duration",
            validators=[
                wtforms.validators.InputRequired("Vote duration is required"),
                util.validate_vote_duration,
            ],
            default=min_hours,
            description="Minimum number of hours the vote will be open for.",
        )
        subject = wtforms.StringField("Subject", validators=[wtforms.validators.Optional()])
        body = wtforms.TextAreaField(
            "Body",
            validators=[wtforms.validators.Optional()],
            description="Edit the vote email content as needed. Placeholders like [KEY_FINGERPRINT],"
            " [DURATION], [REVIEW_URL], and [YOUR_ASF_ID] will be filled in automatically when the email is sent.",
        )
        submit = wtforms.SubmitField("Send vote email")

    project = release.project

    # The subject can be changed by the user
    # TODO: We should consider not allowing the subject to be changed
    default_subject = f"[VOTE] Release {project.display_name} {version_name}"
    default_body = await construct.start_vote_default(project_name)

    # Must use data, not formdata, otherwise everything breaks
    form = await VoteInitiateForm.create_form(
        data=form_data if (quart.request.method == "POST") else None,
    )
    # Set hidden field data explicitly
    form.release_name.data = release.name

    if quart.request.method == "GET":
        form.subject.data = default_subject
        form.body.data = default_body
    return form


async def _keys_warning(
    release: sql.Release,
) -> bool:
    """Return a warning about keys if there are any issues."""
    if release.committee is None:
        raise base.ASFQuartException("Release has no associated committee", errorcode=400)

    if release.committee.is_podling:
        keys_file_path = util.get_downloads_dir() / "incubator" / release.committee.name / "KEYS"
    else:
        keys_file_path = util.get_downloads_dir() / release.committee.name / "KEYS"
    return not await aiofiles.os.path.isfile(keys_file_path)
