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


import aiofiles.os
import asfquart.base as base
import quart
import quart_wtf.typing as typing
import werkzeug.wrappers.response as response

import atr.construct as construct
import atr.db as db
import atr.db.interaction as interaction
import atr.forms as forms
import atr.get.compose as compose
import atr.get.vote as vote
import atr.log as log
import atr.models.sql as sql
import atr.storage as storage
import atr.template as template
import atr.user as user
import atr.util as util
import atr.web as web


class VoteInitiateForm(forms.Typed):
    """Form for initiating a release vote."""

    release_name = forms.hidden()
    mailing_list = forms.radio("Send vote email to")
    vote_duration = forms.integer(
        "Minimum vote duration", default=72, description="Minimum number of hours the vote will be open for."
    )
    subject = forms.optional("Subject")
    body = forms.textarea(
        "Body",
        description="Edit the vote email content as needed. Placeholders like [KEY_FINGERPRINT],"
        " [DURATION], [REVIEW_URL], and [YOUR_ASF_ID] will be filled in automatically when the email is sent.",
    )
    submit = forms.submit("Send vote email")


async def selected_revision(
    session: web.Committer, project_name: str, version_name: str, revision: str
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
        selected_revision_number = release.latest_revision_number
        if selected_revision_number is None:
            return await session.redirect(compose.selected, error="No revision found for this release")
        if revision != selected_revision_number:
            return await session.redirect(
                compose.selected, error="The selected revision does not match the revision you are voting on"
            )
        response_or_form = await _selected_revision_data(
            release, project_name, version_name, selected_revision_number, data, session
        )
        if not isinstance(response_or_form, VoteInitiateForm):
            return response_or_form
        form = response_or_form

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
        user_tests_address=util.USER_TESTS_ADDRESS,
    )


async def start_vote_manual(
    release: sql.Release,
    selected_revision_number: str,
    session: web.Committer,
    _data: db.Session,
) -> response.Response | str:
    async with storage.write(session) as write:
        wacp = await write.as_project_committee_participant(release.project_name)
        # This verifies the state and sets the phase to RELEASE_CANDIDATE
        error = await wacp.release.promote_to_candidate(release.name, selected_revision_number, vote_manual=True)
    if error:
        import atr.get.root as root

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
    # TODO: Restore the use of min_hours
    min_hours: int,
) -> VoteInitiateForm:
    project = release.project

    # The subject can be changed by the user
    # TODO: We should consider not allowing the subject to be changed
    default_subject = f"[VOTE] Release {project.display_name} {version_name}"
    default_body = await construct.start_vote_default(project_name)

    # Must use data, not formdata, otherwise everything breaks
    form = await VoteInitiateForm.create_form(
        data=form_data if (quart.request.method == "POST") else None,
    )

    # Set defaults
    choices: forms.Choices = sorted([(recipient, recipient) for recipient in permitted_recipients])
    if quart.request.method == "GET":
        # Defaults for GET requests
        form.subject.data = default_subject
        form.body.data = default_body
        # Choices and defaults for mailing list
        forms.choices(form.mailing_list, choices, default=util.USER_TESTS_ADDRESS)
    else:
        forms.choices(form.mailing_list, choices)
    # Hidden field
    form.release_name.data = release.name
    # Description
    form.mailing_list.description = """\
NOTE: The options to send to the user-tests mailing
list and yourself are provided for testing purposes
only, and will not be available in the finished
version of ATR."""

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


async def _selected_revision_data(
    release: sql.Release,
    project_name: str,
    version_name: str,
    revision: str,
    data: db.Session,
    session: web.Committer,
) -> response.Response | str | VoteInitiateForm:
    committee = release.committee
    if committee is None:
        raise base.ASFQuartException("Release has no associated committee", errorcode=400)

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
    if not (user.is_committee_member(committee, session.uid) or user.is_admin(session.uid)):
        return await session.redirect(
            compose.selected,
            error="You must be on the PMC of this project to start a vote",
            project_name=project_name,
            version_name=version_name,
            revision=revision,
        )

    # committee = util.unwrap(release.committee)
    permitted_recipients = util.permitted_voting_recipients(session.uid, committee.name)
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
        log.info(f"voting.selected_revision: email to: {email_to}")
        vote_duration_choice: int = util.unwrap(form.vote_duration.data)
        subject_data: str = util.unwrap(form.subject.data)
        body_data: str = util.unwrap(form.body.data)
        async with storage.write_as_committee_participant(committee.name) as wacp:
            _task = await wacp.vote.start(
                email_to,
                project_name,
                version_name,
                revision,
                vote_duration_choice,
                subject_data,
                body_data,
                session.uid,
                session.fullname,
                release=release,
                promote=True,
                permitted_recipients=permitted_recipients,
            )
        return await session.redirect(
            vote.selected,
            success=f"The vote announcement email will soon be sent to {email_to}.",
            project_name=project_name,
            version_name=version_name,
        )
    return form
