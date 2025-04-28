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
import atr.routes.compose as compose
import atr.routes.root as root
import atr.routes.upload as upload
import atr.tasks.sbom as sbom
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


# TODO: Should we deprecate this and ensure compose covers it all?
# If we did that, we'd lose the exhaustive use of the abstraction
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
        # TODO: Move to somewhere appropriate
        "phase-view.html",
        file_stats=file_stats,
        release=release,
        format_datetime=routes.format_datetime,
        format_file_size=routes.format_file_size,
        format_permissions=routes.format_permissions,
        phase="release candidate draft",
        phase_key="draft",
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
