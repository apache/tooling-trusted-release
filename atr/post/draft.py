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

from __future__ import annotations

import pathlib

import aiofiles.os
import aioshutil
import asfquart.base as base
import quart

import atr.blueprints.post as post
import atr.construct as construct
import atr.forms as forms
import atr.get as get
import atr.log as log
import atr.models.sql as sql
import atr.shared as shared
import atr.storage as storage
import atr.util as util
import atr.web as web


class VotePreviewForm(forms.Typed):
    body = forms.textarea("Body")
    # TODO: Validate the vote duration again?
    # Probably not necessary in a preview
    # Note that tasks/vote.py does not use this form
    vote_duration = forms.integer("Vote duration")


@post.committer("/draft/delete")
async def delete(session: web.Committer) -> web.WerkzeugResponse:
    """Delete a candidate draft and all its associated files."""
    import atr.get as get

    form = await shared.draft.DeleteForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        for _field, errors in form.errors.items():
            for error in errors:
                await quart.flash(f"{error}", "error")
        return await session.redirect(get.root.index)

    release_name = form.release_name.data
    if not release_name:
        return await session.redirect(get.root.index, error="Missing required parameters")

    project_name = form.project_name.data
    if not project_name:
        return await session.redirect(get.root.index, error="Missing required parameters")

    version_name = form.version_name.data
    if not version_name:
        return await session.redirect(get.root.index, error="Missing required parameters")

    await session.check_access(project_name)

    # Delete the metadata from the database
    async with storage.write(session) as write:
        wacp = await write.as_project_committee_participant(project_name)
        await wacp.release.delete(
            project_name, version_name, phase=sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT, include_downloads=False
        )

    # Delete the files on disk, including all revisions
    # We can't use util.release_directory_base here because we don't have the release object
    draft_dir = util.get_unfinished_dir() / project_name / version_name
    if await aiofiles.os.path.exists(draft_dir):
        # Believe this to be another bug in mypy Protocol handling
        # TODO: Confirm that this is a bug, and report upstream
        # Changing it to str(...) doesn't work either
        # Yet it works in preview.py
        await aioshutil.rmtree(draft_dir)  # type: ignore[call-arg]

    return await session.redirect(get.root.index, success="Candidate draft deleted successfully")


@post.committer("/draft/delete-file/<project_name>/<version_name>")
async def delete_file(session: web.Committer, project_name: str, version_name: str) -> web.WerkzeugResponse:
    """Delete a specific file from the release candidate, creating a new revision."""
    await session.check_access(project_name)

    form = await shared.draft.DeleteFileForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        error_summary = []
        for key, value in form.errors.items():
            error_summary.append(f"{key}: {value}")
        await quart.flash("; ".join(error_summary), "error")
        return await session.redirect(get.compose.selected, project_name=project_name, version_name=version_name)

    rel_path_to_delete = pathlib.Path(str(form.file_path.data))

    try:
        async with storage.write(session) as write:
            wacp = await write.as_project_committee_participant(project_name)
            metadata_files_deleted = await wacp.release.delete_file(project_name, version_name, rel_path_to_delete)
    except Exception as e:
        log.exception("Error deleting file:")
        await quart.flash(f"Error deleting file: {e!s}", "error")
        return await session.redirect(get.compose.selected, project_name=project_name, version_name=version_name)

    success_message = f"File '{rel_path_to_delete.name}' deleted successfully"
    if metadata_files_deleted:
        success_message += (
            f", and {metadata_files_deleted} associated metadata "
            f"file{'' if metadata_files_deleted == 1 else 's'} deleted"
        )
    return await session.redirect(
        get.compose.selected, success=success_message, project_name=project_name, version_name=version_name
    )


@post.committer("/draft/fresh/<project_name>/<version_name>")
async def fresh(session: web.Committer, project_name: str, version_name: str) -> web.WerkzeugResponse:
    """Restart all checks for a whole release candidate draft."""
    # Admin only button, but it's okay if users find and use this manually
    await session.check_access(project_name)

    await util.validate_empty_form()
    # Restart checks by creating a new identical draft revision
    # This doesn't make sense unless the checks themselves have been updated
    # Therefore we only show the button for this to admins
    description = "Empty revision to restart all checks for the whole release candidate draft"
    async with storage.write(session) as write:
        wacp = await write.as_project_committee_participant(project_name)
        async with wacp.revision.create_and_manage(
            project_name, version_name, session.uid, description=description
        ) as _creating:
            pass

    return await session.redirect(
        get.compose.selected,
        project_name=project_name,
        version_name=version_name,
        success="All checks restarted",
    )


@post.committer("/draft/hashgen/<project_name>/<version_name>/<path:file_path>")
async def hashgen(session: web.Committer, project_name: str, version_name: str, file_path: str) -> web.WerkzeugResponse:
    """Generate an sha256 or sha512 hash file for a candidate draft file, creating a new revision."""
    await session.check_access(project_name)

    # Get the hash type from the form data
    # TODO: This is not truly empty, so make a form object for this
    await util.validate_empty_form()
    form = await quart.request.form
    hash_type = form.get("hash_type")
    if hash_type not in {"sha256", "sha512"}:
        raise base.ASFQuartException(f"Invalid hash type '{hash_type}'. Supported types: sha256, sha512", errorcode=400)

    rel_path = pathlib.Path(file_path)

    try:
        async with storage.write(session) as write:
            wacp = await write.as_project_committee_participant(project_name)
            await wacp.release.generate_hash_file(project_name, version_name, rel_path, hash_type)

    except Exception as e:
        log.exception("Error generating hash file:")
        await quart.flash(f"Error generating hash file: {e!s}", "error")
        return await session.redirect(get.compose.selected, project_name=project_name, version_name=version_name)

    return await session.redirect(
        get.compose.selected,
        success=f"{hash_type} file generated successfully",
        project_name=project_name,
        version_name=version_name,
    )


@post.committer("/draft/sbomgen/<project_name>/<version_name>/<path:file_path>")
async def sbomgen(session: web.Committer, project_name: str, version_name: str, file_path: str) -> web.WerkzeugResponse:
    """Generate a CycloneDX SBOM file for a candidate draft file, creating a new revision."""
    await session.check_access(project_name)

    await util.validate_empty_form()
    rel_path = pathlib.Path(file_path)

    # Check that the file is a .tar.gz archive before creating a revision
    if not (file_path.endswith(".tar.gz") or file_path.endswith(".tgz")):
        raise base.ASFQuartException(
            f"SBOM generation requires .tar.gz or .tgz files. Received: {file_path}", errorcode=400
        )

    try:
        description = "SBOM generation through web interface"
        async with storage.write(session) as write:
            wacp = await write.as_project_committee_participant(project_name)
            async with wacp.revision.create_and_manage(
                project_name, version_name, session.uid, description=description
            ) as creating:
                # Uses new_revision_number in a functional way
                path_in_new_revision = creating.interim_path / rel_path
                sbom_path_rel = rel_path.with_suffix(rel_path.suffix + ".cdx.json").name
                sbom_path_in_new_revision = creating.interim_path / rel_path.parent / sbom_path_rel

                # Check that the source file exists in the new revision
                if not await aiofiles.os.path.exists(path_in_new_revision):
                    log.error(f"Source file {rel_path} not found in new revision for SBOM generation.")
                    raise web.FlashError("Source artifact file not found in the new revision.")

                # Check that the SBOM file does not already exist in the new revision
                if await aiofiles.os.path.exists(sbom_path_in_new_revision):
                    raise base.ASFQuartException("SBOM file already exists", errorcode=400)

            if creating.new is None:
                raise web.FlashError("Internal error: New revision not found")

            # Create and queue the task, using paths within the new revision
            sbom_task = await wacp.sbom.generate_cyclonedx(
                project_name, version_name, creating.new.number, path_in_new_revision, sbom_path_in_new_revision
            )
            await wacp.sbom.generate_cyclonedx_wait(sbom_task)

    except Exception as e:
        log.exception("Error generating SBOM:")
        await quart.flash(f"Error generating SBOM: {e!s}", "error")
        return await session.redirect(get.compose.selected, project_name=project_name, version_name=version_name)

    return await session.redirect(
        get.compose.selected,
        success=f"SBOM generation task queued for {rel_path.name}",
        project_name=project_name,
        version_name=version_name,
    )


@post.committer("/draft/vote/preview/<project_name>/<version_name>")
async def vote_preview(
    session: web.Committer, project_name: str, version_name: str
) -> web.QuartResponse | web.WerkzeugResponse | str:
    """Show the vote email preview for a release."""
    import atr.get as get

    form = await VotePreviewForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        return await session.redirect(get.root.index, error="Invalid form data")

    release = await session.release(project_name, version_name)
    if release.committee is None:
        raise web.FlashError("Release has no associated committee")

    form_body: str = util.unwrap(form.body.data)
    asfuid = session.uid
    project_name = release.project.name
    version_name = release.version
    vote_duration: int = util.unwrap(form.vote_duration.data)

    body = await construct.start_vote_body(
        form_body,
        construct.StartVoteOptions(
            asfuid=asfuid,
            fullname=session.fullname,
            project_name=project_name,
            version_name=version_name,
            vote_duration=vote_duration,
        ),
    )
    return web.TextResponse(body)
