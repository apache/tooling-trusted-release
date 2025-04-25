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

"""draft.py"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import logging
import pathlib
from typing import TYPE_CHECKING, Protocol, TypeVar

import aiofiles.os
import aioshutil
import asfquart.base as base
import quart
import wtforms

import atr.analysis as analysis
import atr.db as db
import atr.db.models as models
import atr.mail as mail
import atr.revision as revision
import atr.routes as routes
import atr.routes.candidate as candidate
import atr.routes.compose as compose
import atr.routes.root as root
import atr.routes.upload as upload
import atr.tasks.sbom as sbom
import atr.tasks.vote as tasks_vote
import atr.user as user
import atr.util as util

if TYPE_CHECKING:
    import werkzeug.wrappers.response as response

# _CONFIG: Final = config.get()
# _LOGGER: Final = logging.getLogger(__name__)


T = TypeVar("T")


class AddProtocol(Protocol):
    """Protocol for forms that create release candidate drafts."""

    version_name: wtforms.StringField
    project_name: wtforms.SelectField


class DeleteFileForm(util.QuartFormTyped):
    """Form for deleting a file."""

    file_path = wtforms.StringField("File path", validators=[wtforms.validators.InputRequired("File path is required")])
    submit = wtforms.SubmitField("Delete file")


class DeleteForm(util.QuartFormTyped):
    """Form for deleting a candidate draft."""

    candidate_draft_name = wtforms.StringField(
        "Candidate draft name", validators=[wtforms.validators.InputRequired("Candidate draft name is required")]
    )
    confirm_delete = wtforms.StringField(
        "Confirmation",
        validators=[
            wtforms.validators.InputRequired("Confirmation is required"),
            wtforms.validators.Regexp("^DELETE$", message="Please type DELETE to confirm"),
        ],
    )
    submit = wtforms.SubmitField("Delete candidate draft")


@routes.committer("/draft/delete", methods=["POST"])
async def delete(session: routes.CommitterSession) -> response.Response:
    """Delete a candidate draft and all its associated files."""
    form = await DeleteForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        for _field, errors in form.errors.items():
            for error in errors:
                await quart.flash(f"{error}", "error")
        return await session.redirect(root.index)

    candidate_draft_name = form.candidate_draft_name.data
    if not candidate_draft_name:
        return await session.redirect(root.index, error="Missing required parameters")

    # Extract project name and version
    try:
        project_name, version = candidate_draft_name.rsplit("-", 1)
    except ValueError:
        return await session.redirect(root.index, error="Invalid candidate draft name format")
    await session.check_access(project_name)

    # Delete the metadata from the database
    async with db.session() as data:
        async with data.begin():
            try:
                await _delete_candidate_draft(data, candidate_draft_name)
            except Exception as e:
                logging.exception("Error deleting candidate draft:")
                return await session.redirect(root.index, error=f"Error deleting candidate draft: {e!s}")

    # Delete the files on disk, including all revisions
    # We can't use util.release_directory_base here because we don't have the release object
    draft_dir = util.get_release_candidate_draft_dir() / project_name / version
    if await aiofiles.os.path.exists(draft_dir):
        # Believe this to be another bug in mypy Protocol handling
        # TODO: Confirm that this is a bug, and report upstream
        # Changing it to str(...) doesn't work either
        # Yet it works in preview.py
        await aioshutil.rmtree(draft_dir)  # type: ignore[call-arg]

    return await session.redirect(root.index, success="Candidate draft deleted successfully")


@routes.committer("/draft/delete-file/<project_name>/<version_name>", methods=["POST"])
async def delete_file(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response:
    """Delete a specific file from the release candidate, creating a new revision."""
    await session.check_access(project_name)

    form = await DeleteFileForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        return await session.redirect(compose.selected, project_name=project_name, version_name=version_name)

    rel_path_to_delete = pathlib.Path(str(form.file_path.data))
    metadata_files_deleted = 0

    try:
        async with revision.create_and_manage(project_name, version_name, session.uid) as (
            new_revision_dir,
            new_revision_name,
        ):
            # Path to delete within the new revision directory
            path_in_new_revision = new_revision_dir / rel_path_to_delete

            # Check that the file exists in the new revision
            if not await aiofiles.os.path.exists(path_in_new_revision):
                # This indicates a potential severe issue with hard linking or logic
                logging.error(
                    f"SEVERE ERROR! File {rel_path_to_delete} not found in new revision"
                    f" {new_revision_name} before deletion"
                )
                raise routes.FlashError("File to delete was not found in the new revision")

            # Check whether the file is an artifact
            if analysis.is_artifact(path_in_new_revision):
                # If so, delete all associated metadata files in the new revision
                for p in await util.paths_recursive(path_in_new_revision.parent):
                    # Construct full path within the new revision
                    metadata_path_obj = new_revision_dir / p
                    if p.name.startswith(rel_path_to_delete.name + "."):
                        await aiofiles.os.remove(metadata_path_obj)
                        metadata_files_deleted += 1

            # Delete the file
            await aiofiles.os.remove(path_in_new_revision)

    except Exception as e:
        logging.exception("Error deleting file:")
        await quart.flash(f"Error deleting file: {e!s}", "error")
        return await session.redirect(compose.selected, project_name=project_name, version_name=version_name)

    success_message = f"File '{rel_path_to_delete.name}' deleted successfully"
    if metadata_files_deleted:
        success_message += (
            f", and {metadata_files_deleted} associated metadata "
            f"file{'' if metadata_files_deleted == 1 else 's'} deleted"
        )
    return await session.redirect(
        compose.selected, success=success_message, project_name=project_name, version_name=version_name
    )


@routes.committer("/draft/fresh/<project_name>/<version_name>", methods=["POST"])
async def fresh(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response:
    """Restart all checks for a whole release candidate draft."""
    # Admin only button, but it's okay if users find and use this manually
    await session.check_access(project_name)

    # Restart checks by creating a new identical draft revision
    # This doesn't make sense unless the checks themselves have been updated
    # Therefore we only show the button for this to admins
    async with revision.create_and_manage(project_name, version_name, session.uid) as (
        _new_revision_dir,
        _new_revision_name,
    ):
        ...

    return await session.redirect(
        compose.selected,
        project_name=project_name,
        version_name=version_name,
        success="All checks restarted",
    )


@routes.committer("/draft/hashgen/<project_name>/<version_name>/<path:file_path>", methods=["POST"])
async def hashgen(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response:
    """Generate an sha256 or sha512 hash file for a candidate draft file, creating a new revision."""
    await session.check_access(project_name)

    # Get the hash type from the form data
    # This is just a button, so we don't make a whole form validation schema for it
    form = await quart.request.form
    hash_type = form.get("hash_type")
    if hash_type not in {"sha256", "sha512"}:
        raise base.ASFQuartException("Invalid hash type", errorcode=400)

    rel_path = pathlib.Path(file_path)

    try:
        async with revision.create_and_manage(project_name, version_name, session.uid) as (
            new_revision_dir,
            new_revision_name,
        ):
            path_in_new_revision = new_revision_dir / rel_path
            hash_path_rel = rel_path.name + f".{hash_type}"
            hash_path_in_new_revision = new_revision_dir / rel_path.parent / hash_path_rel

            # Check that the source file exists in the new revision
            if not await aiofiles.os.path.exists(path_in_new_revision):
                logging.error(
                    f"Source file {rel_path} not found in new revision {new_revision_name} for hash generation."
                )
                raise routes.FlashError("Source file not found in the new revision.")

            # Check that the hash file does not already exist in the new revision
            if await aiofiles.os.path.exists(hash_path_in_new_revision):
                raise base.ASFQuartException(f"{hash_type} file already exists", errorcode=400)

            # Read the source file from the new revision and compute the hash
            hash_obj = hashlib.sha256() if hash_type == "sha256" else hashlib.sha512()
            async with aiofiles.open(path_in_new_revision, "rb") as f:
                while chunk := await f.read(8192):
                    hash_obj.update(chunk)

            # Write the hash file into the new revision
            hash_value = hash_obj.hexdigest()
            async with aiofiles.open(hash_path_in_new_revision, "w") as f:
                await f.write(f"{hash_value}  {rel_path.name}\n")

    except Exception as e:
        logging.exception("Error generating hash file:")
        await quart.flash(f"Error generating hash file: {e!s}", "error")
        return await session.redirect(compose.selected, project_name=project_name, version_name=version_name)

    return await session.redirect(
        compose.selected,
        success=f"{hash_type} file generated successfully",
        project_name=project_name,
        version_name=version_name,
    )


@routes.committer("/draft/sbomgen/<project_name>/<version_name>/<path:file_path>", methods=["POST"])
async def sbomgen(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response:
    """Generate a CycloneDX SBOM file for a candidate draft file, creating a new revision."""
    await session.check_access(project_name)

    rel_path = pathlib.Path(file_path)

    # Check that the file is a .tar.gz archive before creating a revision
    if not (file_path.endswith(".tar.gz") or file_path.endswith(".tgz")):
        raise base.ASFQuartException("SBOM generation is only supported for .tar.gz files", errorcode=400)

    try:
        async with revision.create_and_manage(project_name, version_name, session.uid) as (
            new_revision_dir,
            new_revision_name,
        ):
            path_in_new_revision = new_revision_dir / rel_path
            sbom_path_rel = rel_path.with_suffix(rel_path.suffix + ".cdx.json").name
            sbom_path_in_new_revision = new_revision_dir / rel_path.parent / sbom_path_rel

            # Check that the source file exists in the new revision
            if not await aiofiles.os.path.exists(path_in_new_revision):
                logging.error(
                    f"Source file {rel_path} not found in new revision {new_revision_name} for SBOM generation."
                )
                raise routes.FlashError("Source artifact file not found in the new revision.")

            # Check that the SBOM file does not already exist in the new revision
            if await aiofiles.os.path.exists(sbom_path_in_new_revision):
                raise base.ASFQuartException("SBOM file already exists", errorcode=400)

            # Create and queue the task, using paths within the new revision
            async with db.session() as data:
                # We still need release.name for the task metadata
                release = await session.release(project_name, version_name, data=data)

                sbom_task = models.Task(
                    task_type=models.TaskType.SBOM_GENERATE_CYCLONEDX,
                    task_args=sbom.GenerateCycloneDX(
                        artifact_path=str(path_in_new_revision.resolve()),
                        output_path=str(sbom_path_in_new_revision.resolve()),
                    ).model_dump(),
                    added=datetime.datetime.now(datetime.UTC),
                    status=models.TaskStatus.QUEUED,
                    release_name=release.name,
                    draft_revision=new_revision_name,
                )
                data.add(sbom_task)
                await data.commit()

                # We must wait until the sbom_task is complete before we can queue checks
                # Maximum wait time is 60 * 100ms = 6000ms
                for _attempt in range(60):
                    await data.refresh(sbom_task)
                    if sbom_task.status != models.TaskStatus.QUEUED:
                        break
                    # Wait 100ms before checking again
                    await asyncio.sleep(0.1)

    except Exception as e:
        logging.exception("Error generating SBOM:")
        await quart.flash(f"Error generating SBOM: {e!s}", "error")
        return await session.redirect(compose.selected, project_name=project_name, version_name=version_name)

    return await session.redirect(
        compose.selected,
        success=f"SBOM generation task queued for {rel_path.name}",
        project_name=project_name,
        version_name=version_name,
    )


@routes.committer("/draft/svnload/<project_name>/<version_name>", methods=["POST"])
async def svnload(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Import files from SVN into a draft."""
    await session.check_access(project_name)
    form = await upload.SvnImportForm.create_form()
    release = await session.release(project_name, version_name, with_project=False)

    if not await form.validate_on_submit():
        for _field, errors in form.errors.items():
            for error in errors:
                await quart.flash(f"{error}", "error")
        return await session.redirect(
            upload.selected,
            project_name=project_name,
            version_name=version_name,
        )

    try:
        task_args = {
            "svn_url": str(form.svn_url.data),
            "revision": str(form.revision.data),
            "target_subdirectory": str(form.target_subdirectory.data) if form.target_subdirectory.data else None,
            "project_name": project_name,
            "version_name": version_name,
            "asf_uid": session.uid,
        }
        async with db.session() as data:
            svn_import_task = models.Task(
                task_type=models.TaskType.SVN_IMPORT_FILES,
                task_args=task_args,
                added=datetime.datetime.now(datetime.UTC),
                status=models.TaskStatus.QUEUED,
                release_name=release.name,
            )
            data.add(svn_import_task)
            await data.commit()

    except Exception:
        logging.exception("Error queueing SVN import task:")
        return await session.redirect(
            upload.selected,
            error="Error queueing SVN import task",
            project_name=project_name,
            version_name=version_name,
        )

    return await session.redirect(
        compose.selected,
        success="SVN import task queued successfully",
        project_name=project_name,
        version_name=version_name,
    )


@routes.committer("/draft/tools/<project_name>/<version_name>/<path:file_path>")
async def tools(session: routes.CommitterSession, project_name: str, version_name: str, file_path: str) -> str:
    """Show the tools for a specific file."""
    await session.check_access(project_name)
    release = await session.release(project_name, version_name)

    full_path = str(util.release_directory(release) / file_path)

    # Check that the file exists
    if not await aiofiles.os.path.exists(full_path):
        raise base.ASFQuartException("File does not exist", errorcode=404)

    modified = int(await aiofiles.os.path.getmtime(full_path))
    file_size = await aiofiles.os.path.getsize(full_path)

    file_data = {
        "filename": pathlib.Path(file_path).name,
        "bytes_size": file_size,
        "uploaded": datetime.datetime.fromtimestamp(modified, tz=datetime.UTC),
    }

    return await quart.render_template(
        "draft-tools.html",
        asf_id=session.uid,
        project_name=project_name,
        version_name=version_name,
        file_path=file_path,
        file_data=file_data,
        release=release,
        format_file_size=routes.format_file_size,
    )


@routes.committer("/draft/view/<project_name>/<version_name>")
async def view(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """View all the files in the rsync upload directory for a release."""
    await session.check_access(project_name)
    release = await session.release(project_name, version_name)

    # Convert async generator to list
    file_stats = [
        stat
        async for stat in util.content_list(
            util.get_release_candidate_draft_dir(), project_name, version_name, release.revision
        )
    ]

    return await quart.render_template(
        "phase-view.html",
        file_stats=file_stats,
        release=release,
        format_datetime=routes.format_datetime,
        format_file_size=routes.format_file_size,
        format_permissions=routes.format_permissions,
        phase="release candidate draft",
        phase_key="draft",
    )


@routes.committer("/file/<project_name>/<version_name>/<path:file_path>")
async def view_path(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response | str:
    """View the content of a specific file in the release candidate draft."""
    await session.check_access(project_name)
    release = await session.release(project_name, version_name)

    # Limit to 256 KiB
    _max_view_size = 256 * 1024
    full_path = util.release_directory(release) / file_path

    # Attempt to get an archive listing
    # This will be None if the file is not an archive
    content_listing = await util.archive_listing(full_path)

    content, is_text, is_truncated, error_message = await util.read_file_for_viewer(full_path, _max_view_size)
    return await quart.render_template(
        "phase-view-path.html",
        release=release,
        project_name=project_name,
        version_name=version_name,
        file_path=file_path,
        content=content,
        is_text=is_text,
        is_truncated=is_truncated,
        error_message=error_message,
        content_listing=content_listing,
        format_file_size=routes.format_file_size,
        phase_key="draft",
        max_view_size=routes.format_file_size(_max_view_size),
    )


@routes.committer("/draft/vote/preview", methods=["POST"])
async def vote_preview(session: routes.CommitterSession) -> quart.wrappers.response.Response | response.Response | str:
    """Show the vote email preview for a release."""

    class VotePreviewForm(util.QuartFormTyped):
        body = wtforms.TextAreaField("Body", validators=[wtforms.validators.InputRequired("Body is required")])
        asfuid = wtforms.StringField("ASF ID", validators=[wtforms.validators.InputRequired("ASF ID is required")])
        # TODO: Validate the vote duration again? Probably not necessary in a preview
        # Note that tasks/vote.py does not use this form
        vote_duration = wtforms.IntegerField(
            "Vote duration", validators=[wtforms.validators.InputRequired("Vote duration is required")]
        )

    form = await VotePreviewForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        return await session.redirect(root.index, error="Invalid form data")

    body = await mail.generate_preview(
        util.unwrap(form.body.data), util.unwrap(form.asfuid.data), util.unwrap(form.vote_duration.data)
    )
    return quart.Response(body, mimetype="text/plain")


# TODO: Rename to vote.revision?
@routes.committer("/vote/<project_name>/<version>/<revision>", methods=["GET", "POST"])
async def vote_start(
    session: routes.CommitterSession, project_name: str, version: str, revision: str
) -> response.Response | str:
    """Show the vote initiation form for a release."""
    await session.check_access(project_name)
    async with db.session() as data:
        project = await data.project(name=project_name).demand(routes.FlashError("Project not found"))
        release = await data.release(project_name=project.name, version=version, _committee=True).demand(
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
                error = await _promote(data, release.name, project_name, version, revision)
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

            resolve_release: routes.RouteHandler[str] = candidate.resolve_release  # type: ignore[has-type]
            return await session.redirect(
                resolve_release,
                success=f"The vote announcement email will soon be sent to {email_to}.",
                project_name=project_name,
                version_name=version,
            )

        # For GET requests or failed POST validation
        return await quart.render_template(
            "draft-vote-start.html",
            release=release,
            form=form,
            revision=revision,
        )


async def _delete_candidate_draft(data: db.Session, candidate_draft_name: str) -> None:
    """Delete a candidate draft and all its associated files."""
    # Check that the release exists
    # TODO: Use session.release here
    release = await data.release(name=candidate_draft_name, _project=True, _packages=True).get()
    if not release:
        raise routes.FlashError("Candidate draft not found")
    if release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
        raise routes.FlashError("Candidate draft is not in the release candidate draft phase")

    # Delete all associated packages first
    for package in release.packages:
        await data.delete(package)

    # Delete any parent links
    await data.ns_text_del_all(release.name + " draft")
    await data.ns_text_del_all(release.name + " preview")
    # Delete the release record
    await data.delete(release)


async def _promote(
    data: db.Session,
    candidate_draft_name: str,
    project_name: str,
    version_name: str,
    revision_name: str,
) -> str | None:
    """Promote a candidate draft to a new phase."""
    # Get the release
    # TODO: Use session.release here
    release = await data.release(name=candidate_draft_name, _project=True).demand(
        routes.FlashError("Candidate draft not found")
    )

    # Verify that it's in the correct phase
    if release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
        return "This release is not in the candidate draft phase"

    base_dir = util.release_directory_base(release)
    # Use the directory of the specified revision
    # TODO: This ensures that we promote the correct revision, but does not stop conflicts
    # We need to obtain a lock when promoting
    source_dir = base_dir / revision_name
    target_dir: pathlib.Path

    # Count how many files are in the source directory
    file_count = await util.number_of_release_files(release)
    if file_count == 0:
        return "This candidate draft is empty, containing no files"

    # Promote it to the target phase
    # TODO: Obtain a lock for this
    # NOTE: The functionality for skipping phases has been removed
    release.stage = models.ReleaseStage.RELEASE_CANDIDATE
    release.phase = models.ReleasePhase.RELEASE_CANDIDATE
    release.revision = None
    target_dir = util.release_directory(release)

    if await aiofiles.os.path.exists(target_dir):
        return f"Target directory {target_dir.name} already exists"

    await data.commit()
    # We updated the release
    # This could act like a lock, but it would be difficult
    # TODO: Ideally we'd store the revision on the release object instead
    # Then we could make it atomic through the database

    logging.warning(f"Moving {source_dir} to {target_dir} (base: {base_dir})")
    await aioshutil.move(str(source_dir), str(target_dir))
    await aioshutil.rmtree(str(base_dir))  # type: ignore[call-arg]

    return None
