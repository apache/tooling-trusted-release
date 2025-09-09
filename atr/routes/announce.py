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

from typing import Any

import quart
import werkzeug.wrappers.response as response

# TODO: Improve upon the routes_release pattern
import atr.config as config
import atr.construct as construct
import atr.forms as forms
import atr.models.sql as sql
import atr.routes as routes
import atr.routes.release as routes_release
import atr.storage as storage
import atr.template as template
import atr.util as util


class AnnounceError(Exception):
    """Exception for announce errors."""


class AnnounceForm(forms.Typed):
    """Form for announcing a release preview."""

    preview_name = forms.hidden()
    preview_revision = forms.hidden()
    mailing_list = forms.radio("Send vote email to")
    download_path_suffix = forms.optional("Download path suffix")
    confirm_announce = forms.boolean("Confirm")
    subject = forms.optional("Subject")
    body = forms.textarea("Body", optional=True)
    submit = forms.submit("Send announcement email")


class DeleteForm(forms.Typed):
    """Form for deleting a release preview."""

    preview_name = forms.string("Preview name")
    confirm_delete = forms.string(
        "Confirmation",
        validators=forms.constant("DELETE"),
    )
    submit = forms.submit("Delete preview")


@routes.committer("/announce/<project_name>/<version_name>")
async def selected(session: routes.CommitterSession, project_name: str, version_name: str) -> str | response.Response:
    """Allow the user to announce a release preview."""
    await session.check_access(project_name)

    release = await session.release(
        project_name, version_name, with_committee=True, phase=sql.ReleasePhase.RELEASE_PREVIEW
    )
    announce_form = await _create_announce_form_instance(util.permitted_announce_recipients(session.uid))
    # Hidden fields
    announce_form.preview_name.data = release.name
    # There must be a revision to announce
    announce_form.preview_revision.data = release.unwrap_revision_number

    # Variables used in defaults for subject and body
    project_display_name = release.project.display_name or release.project.name

    # The subject cannot be changed by the user
    announce_form.subject.data = f"[ANNOUNCE] {project_display_name} {version_name} released"
    # The body can be changed, either from VoteTemplate or from the form
    announce_form.body.data = await construct.announce_release_default(project_name)
    # The download path suffix can be changed
    # The defaults depend on whether the project is top level or not
    if (committee := release.project.committee) is None:
        raise ValueError("Release has no committee")
    top_level_project = release.project.name == util.unwrap(committee.name)
    # These defaults are as per #136, but we allow the user to change the result
    announce_form.download_path_suffix.data = (
        "/" if top_level_project else f"/{release.project.name}-{release.version}/"
    )
    # This must NOT end with a "/"
    description_download_prefix = f"https://{config.get().APP_HOST}/downloads"
    if committee.is_podling:
        description_download_prefix += "/incubator"
    description_download_prefix += f"/{committee.name}"
    announce_form.download_path_suffix.description = f"The URL will be {description_download_prefix} plus this suffix"

    return await template.render(
        "announce-selected.html",
        release=release,
        announce_form=announce_form,
        user_tests_address=util.USER_TESTS_ADDRESS,
    )


@routes.committer("/announce/<project_name>/<version_name>", methods=["POST"])
async def selected_post(
    session: routes.CommitterSession, project_name: str, version_name: str
) -> str | response.Response:
    """Handle the announcement form submission and promote the preview to release."""
    await session.check_access(project_name)

    permitted_recipients = util.permitted_announce_recipients(session.uid)
    announce_form = await _create_announce_form_instance(
        permitted_recipients,
        data=await quart.request.form,
    )

    if not (await announce_form.validate_on_submit()):
        error_message = "Invalid submission"
        if announce_form.errors:
            error_details = "; ".join([f"{field}: {', '.join(errs)}" for field, errs in announce_form.errors.items()])
            error_message = f"{error_message}: {error_details}"

        # Render the page again, with errors
        release: sql.Release = await session.release(
            project_name, version_name, with_committee=True, phase=sql.ReleasePhase.RELEASE_PREVIEW
        )
        await quart.flash(error_message, "error")
        return await template.render("announce-selected.html", release=release, announce_form=announce_form)

    recipient = str(announce_form.mailing_list.data)
    if recipient not in permitted_recipients:
        raise AnnounceError(f"You are not permitted to send announcements to {recipient}")

    subject = str(announce_form.subject.data)
    body = str(announce_form.body.data)
    preview_revision_number = str(announce_form.preview_revision.data)
    download_path_suffix = _download_path_suffix_validated(announce_form)

    try:
        async with storage.write_as_project_committee_member(project_name, session.uid) as wacm:
            await wacm.announce.release(
                project_name,
                version_name,
                preview_revision_number,
                recipient,
                subject,
                body,
                download_path_suffix,
                session.uid,
                session.fullname,
            )
    except storage.AccessError as e:
        return await session.redirect(selected, error=str(e), project_name=project_name, version_name=version_name)

    routes_release_finished = routes_release.finished  # type: ignore[has-type]
    return await session.redirect(
        routes_release_finished,
        success="Preview successfully announced",
        project_name=project_name,
    )


async def _create_announce_form_instance(
    permitted_recipients: list[str], *, data: dict[str, Any] | None = None
) -> AnnounceForm:
    """Create and return an instance of the AnnounceForm."""

    mailing_list_choices: forms.Choices = sorted([(recipient, recipient) for recipient in permitted_recipients])
    mailing_list_default = util.USER_TESTS_ADDRESS

    form_instance = await AnnounceForm.create_form(data=data)
    forms.choices(
        form_instance.mailing_list,
        mailing_list_choices,
        mailing_list_default,
    )
    return form_instance


def _download_path_suffix_validated(announce_form: AnnounceForm) -> str:
    download_path_suffix = str(announce_form.download_path_suffix.data)
    if (".." in download_path_suffix) or ("//" in download_path_suffix):
        raise ValueError("Download path suffix must not contain .. or //")
    if download_path_suffix.startswith("./"):
        download_path_suffix = download_path_suffix[1:]
    elif download_path_suffix == ".":
        download_path_suffix = "/"
    if not download_path_suffix.startswith("/"):
        download_path_suffix = "/" + download_path_suffix
    if not download_path_suffix.endswith("/"):
        download_path_suffix = download_path_suffix + "/"
    if "/." in download_path_suffix:
        raise ValueError("Download path suffix must not contain /.")
    return download_path_suffix
