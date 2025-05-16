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
import logging
from typing import TYPE_CHECKING, Any, Protocol

import aiofiles.os
import aioshutil
import quart
import sqlmodel
import werkzeug.wrappers.response as response
import wtforms

import atr.construct as construct
import atr.db as db
import atr.db.models as models
import atr.routes as routes

# TODO: Improve upon the routes_release pattern
import atr.routes.release as routes_release
import atr.tasks.message as message
import atr.util as util

if TYPE_CHECKING:
    import pathlib


class AnnounceFormProtocol(Protocol):
    """Protocol for the dynamically generated AnnounceForm."""

    preview_name: wtforms.HiddenField
    preview_revision: wtforms.HiddenField
    mailing_list: wtforms.RadioField
    confirm_announce: wtforms.BooleanField
    subject: wtforms.StringField
    body: wtforms.TextAreaField
    submit: wtforms.SubmitField

    @property
    def errors(self) -> dict[str, Any]: ...

    async def validate_on_submit(self) -> bool: ...


class DeleteForm(util.QuartFormTyped):
    """Form for deleting a release preview."""

    preview_name = wtforms.StringField(
        "Preview name", validators=[wtforms.validators.InputRequired("Preview name is required")]
    )
    confirm_delete = wtforms.StringField(
        "Confirmation",
        validators=[
            wtforms.validators.InputRequired("Confirmation is required"),
            wtforms.validators.Regexp("^DELETE$", message="Please type DELETE to confirm"),
        ],
    )
    submit = wtforms.SubmitField("Delete preview")


@routes.committer("/announce/<project_name>/<version_name>")
async def selected(session: routes.CommitterSession, project_name: str, version_name: str) -> str | response.Response:
    """Allow the user to announce a release preview."""
    await session.check_access(project_name)

    release = await session.release(
        project_name, version_name, with_committee=True, phase=models.ReleasePhase.RELEASE_PREVIEW
    )
    announce_form = await _create_announce_form_instance(util.permitted_recipients(session.uid))
    # Hidden fields
    announce_form.preview_name.data = release.name
    announce_form.preview_revision.data = release.unwrap_revision_number

    # Variables used in defaults for subject and body
    project_display_name = release.project.display_name or release.project.name

    # The subject cannot be changed by the user
    announce_form.subject.data = f"[ANNOUNCE] {project_display_name} {version_name} released"
    # The body can be changed, either from VoteTemplate or from the form
    announce_form.body.data = await construct.announce_release_default(project_name)
    return await quart.render_template("announce-selected.html", release=release, announce_form=announce_form)


@routes.committer("/announce/<project_name>/<version_name>", methods=["POST"])
async def selected_post(
    session: routes.CommitterSession, project_name: str, version_name: str
) -> str | response.Response:
    """Handle the announcement form submission and promote the preview to release."""
    await session.check_access(project_name)

    permitted_recipients = util.permitted_recipients(session.uid)
    announce_form = await _create_announce_form_instance(permitted_recipients, data=await quart.request.form)

    if not (await announce_form.validate_on_submit()):
        error_message = "Invalid submission"
        if announce_form.errors:
            error_details = "; ".join([f"{field}: {', '.join(errs)}" for field, errs in announce_form.errors.items()])
            error_message = f"{error_message}: {error_details}"

        # Render the page again, with errors
        release: models.Release = await session.release(
            project_name, version_name, with_committee=True, phase=models.ReleasePhase.RELEASE_PREVIEW
        )
        await quart.flash(error_message, "error")
        return await quart.render_template("announce-selected.html", release=release, announce_form=announce_form)

    subject = str(announce_form.subject.data)
    body = str(announce_form.body.data)
    preview_revision_number = str(announce_form.preview_revision.data)

    source: str = ""
    target: str = ""
    source_base: pathlib.Path | None = None

    async with db.session(log_queries=True) as data:
        try:
            release = await session.release(
                project_name,
                version_name,
                phase=models.ReleasePhase.RELEASE_PREVIEW,
                latest_revision_number=preview_revision_number,
                with_revisions=True,
                data=data,
            )

            test_list = "user-tests"
            recipient = f"{test_list}@tooling.apache.org"
            if recipient not in util.permitted_recipients(session.uid):
                return await session.redirect(
                    selected,
                    error=f"You are not permitted to send announcements to {recipient}",
                    project_name=project_name,
                    version_name=version_name,
                )

            body = await construct.announce_release_body(
                body,
                options=construct.AnnounceReleaseOptions(
                    asfuid=session.uid,
                    fullname=session.fullname,
                    project_name=project_name,
                    version_name=version_name,
                ),
            )
            task = models.Task(
                status=models.TaskStatus.QUEUED,
                task_type=models.TaskType.MESSAGE_SEND,
                task_args=message.Send(
                    email_sender=f"{session.uid}@apache.org",
                    email_recipient=recipient,
                    subject=subject,
                    body=body,
                    in_reply_to=None,
                ).model_dump(),
                release_name=release.name,
            )
            data.add(task)

            # Prepare paths for file operations
            source_base = util.release_directory_base(release)
            source = str(source_base / release.unwrap_revision_number)

            await _promote(release, data, preview_revision_number)
            await data.commit()

        except (routes.FlashError, Exception) as e:
            logging.exception("Error during release announcement, database phase:")
            return await session.redirect(
                selected,
                error=f"Error announcing preview: {e!s}",
                project_name=project_name,
                version_name=version_name,
            )

    async with db.session() as data:
        # This must come after updating the release object
        # Do not put it in the data block after data.commit()
        # Otherwise util.release_directory() will not work
        release = await data.release(name=release.name).demand(RuntimeError(f"Release {release.name} does not exist"))
        target = str(util.release_directory(release))
        if await aiofiles.os.path.exists(target):
            raise routes.FlashError("Release already exists")

    try:
        await aioshutil.move(source, target)
        if source_base:
            await aioshutil.rmtree(str(source_base))  # type: ignore[call-arg]
    except Exception as e:
        logging.exception("Error during release announcement, file system phase:")
        return await session.redirect(
            selected,
            error=f"Database updated, but error moving files: {e!s}. Manual cleanup needed.",
            project_name=project_name,
            version_name=version_name,
        )

    routes_release_finished = routes_release.finished  # type: ignore[has-type]
    return await session.redirect(
        routes_release_finished,
        success="Preview successfully announced",
        project_name=project_name,
    )


async def _create_announce_form_instance(
    permitted_recipients: list[str], *, data: dict[str, Any] | None = None
) -> AnnounceFormProtocol:
    """Create and return an instance of the AnnounceForm."""

    class AnnounceForm(util.QuartFormTyped):
        """Form for announcing a release preview."""

        preview_name = wtforms.HiddenField()
        preview_revision = wtforms.HiddenField()
        mailing_list = wtforms.RadioField(
            "Send vote email to",
            choices=sorted([(recipient, recipient) for recipient in permitted_recipients]),
            validators=[wtforms.validators.InputRequired("Mailing list selection is required")],
            default="user-tests@tooling.apache.org",
        )
        confirm_announce = wtforms.BooleanField(
            "Confirm",
            validators=[wtforms.validators.DataRequired("You must confirm to proceed with announcement")],
        )
        subject = wtforms.StringField("Subject", validators=[wtforms.validators.Optional()])
        body = wtforms.TextAreaField("Body", validators=[wtforms.validators.Optional()])
        submit = wtforms.SubmitField("Send announcement email")

    form_instance = await AnnounceForm.create_form(data=data)
    return form_instance


async def _promote(release: models.Release, data: db.Session, preview_revision_number: str) -> None:
    """Promote a release preview to a release and delete its old revisions."""
    via = models.validate_instrumented_attribute

    update_stmt = (
        sqlmodel.update(models.Release)
        .where(
            via(models.Release.name) == release.name,
            via(models.Release.phase) == models.ReleasePhase.RELEASE_PREVIEW,
            models.latest_revision_number_query() == preview_revision_number,
        )
        .values(
            stage=models.ReleaseStage.RELEASE,
            phase=models.ReleasePhase.RELEASE,
            released=datetime.datetime.now(datetime.UTC),
        )
    )
    update_result = await data.execute_query(update_stmt)
    # Avoid a type error with update_result.rowcount
    # Could not find another way to do it, other than using a Protocol
    rowcount: int = getattr(update_result, "rowcount", 0)
    if rowcount != 1:
        raise RuntimeError("A newer revision appeared, please refresh and try again.")

    delete_revisions_stmt = sqlmodel.delete(models.Revision).where(via(models.Revision.release_name) == release.name)
    await data.execute_query(delete_revisions_stmt)
