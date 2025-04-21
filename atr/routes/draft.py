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
import contextlib
import datetime
import hashlib
import logging
import pathlib
import re
from typing import TYPE_CHECKING, Protocol, TypeVar

import aiofiles.os
import aioshutil
import asfquart.base as base
import quart
import sqlmodel
import wtforms

import atr.analysis as analysis
import atr.db as db
import atr.db.models as models
import atr.mail as mail
import atr.revision as revision
import atr.routes as routes
import atr.routes.candidate as candidate
import atr.tasks.sbom as sbom
import atr.tasks.vote as tasks_vote
import atr.user as user
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    import werkzeug.datastructures as datastructures
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


class SvnImportForm(util.QuartFormTyped):
    """Form for importing files from SVN into a draft."""

    svn_url = wtforms.URLField(
        "SVN URL",
        validators=[
            wtforms.validators.InputRequired("SVN URL is required."),
            wtforms.validators.URL(require_tld=False),
        ],
        description="The URL to the public SVN directory",
    )
    revision = wtforms.StringField(
        "Revision",
        default="HEAD",
        validators=[],
        description="Specify an SVN revision number or leave as HEAD for the latest",
    )
    target_subdirectory = wtforms.StringField(
        "Target subdirectory",
        validators=[],
        description="Subdirectory to place imported files, defaulting to the root (optional)",
    )
    submit = wtforms.SubmitField("Queue SVN import task")


@routes.committer("/draft/add", methods=["GET", "POST"])
async def add(session: routes.CommitterSession) -> response.Response | str:
    """Show a page to allow the user to rsync files to candidate drafts."""
    # Allow selection of projects via a query parameter
    preselected_project = quart.request.args.get("project")

    # Do them outside of the template rendering call to ensure order
    # The user_candidate_drafts call can use cached results from user_projects
    user_projects = await user.projects(session.uid, committee_only=True)
    user_candidate_drafts = await session.user_candidate_drafts
    # Sort the project choices reverse chronologically by their creation date
    # This means that if the user added a project recently, it will be at the top of the list
    sorted_projects = sorted(user_projects, key=lambda p: p.created, reverse=True)
    project_choices = [(p.name, p.full_name or p.name) for p in sorted_projects]

    class AddForm(util.QuartFormTyped):
        project_name = wtforms.SelectField("Project", choices=project_choices)
        version_name = wtforms.StringField(
            "Version", validators=[wtforms.validators.InputRequired("Version is required")]
        )
        submit = wtforms.SubmitField("Create candidate draft")

    form = await AddForm.create_form()

    if preselected_project and quart.request.method == "GET":
        # Ensure the preselected project is valid for the user
        if any(p.name == preselected_project for p in user_projects):
            form.project_name.data = preselected_project
        else:
            await quart.flash(f"Project '{preselected_project}' is not available for selection.", "warning")

    if quart.request.method == "POST":
        if not await form.validate_on_submit():
            # TODO: Show the form with errors
            return await session.redirect(add, error="Invalid form data")

        try:
            new_release, project = await create_release_draft(
                project_name=str(form.project_name.data), version=str(form.version_name.data), asf_uid=session.uid
            )
            return await session.redirect(
                overview,
                project_name=project.name,
                version_name=new_release.version,
                success="Release candidate draft created successfully",
            )
        except (routes.FlashError, base.ASFQuartException) as e:
            await quart.flash(str(e), "error")
            # Get the preselected project from the query parameters, then fall through to render the template
            preselected_project = quart.request.args.get("project")

    return await quart.render_template(
        "draft-add.html",
        asf_id=session.uid,
        projects=sorted_projects,
        server_domain=session.host,
        number_of_release_files=util.number_of_release_files,
        candidate_drafts=user_candidate_drafts,
        user_projects=sorted_projects,
        form=form,
        preselected_project=preselected_project,
    )


@routes.committer("/draft/add/<project_name>/<version_name>", methods=["GET", "POST"])
async def add_files(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Show a page to allow the user to add files to a candidate draft."""

    class AddFilesForm(util.QuartFormTyped):
        """Form for adding files to a release candidate."""

        file_name = wtforms.StringField("File name (optional)")
        file_data = wtforms.MultipleFileField(
            "Files", validators=[wtforms.validators.InputRequired("At least one file is required")]
        )
        submit = wtforms.SubmitField("Add files")

        def validate_file_name(self, field: wtforms.Field) -> bool:
            if field.data and len(self.file_data.data) > 1:
                raise wtforms.validators.ValidationError("File name can only be used when uploading a single file")
            return True

    form = await AddFilesForm.create_form()
    if await form.validate_on_submit():
        try:
            file_name = None
            if isinstance(form.file_name.data, str) and form.file_name.data:
                file_name = pathlib.Path(form.file_name.data)
            file_data = form.file_data.data

            number_of_files = await _upload_files(project_name, version_name, session.uid, file_name, file_data)
            return await session.redirect(
                evaluate,
                success=f"{number_of_files} file{'' if number_of_files == 1 else 's'} added successfully",
                project_name=project_name,
                version_name=version_name,
            )
        except Exception as e:
            logging.exception("Error adding file:")
            await quart.flash(f"Error adding file: {e!s}", "error")

    svn_form = await SvnImportForm.create_form()

    async with db.session() as data:
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )
        project_display_name = release.project.display_name

    return await quart.render_template(
        "draft-add-files.html",
        asf_id=session.uid,
        server_domain=session.host,
        project_name=project_name,
        version_name=version_name,
        form=form,
        svn_form=svn_form,
        project_display_name=project_display_name,
    )


async def create_release_draft(project_name: str, version: str, asf_uid: str) -> tuple[models.Release, models.Project]:
    """Creates the initial release draft record and revision directory."""
    # Get the project from the project name
    async with db.session() as data:
        async with data.begin():
            project = await data.project(name=project_name, _committee=True).get()
            if not project:
                raise routes.FlashError(f"Project {project_name} not found")

            # TODO: Temporarily allow committers to start drafts
            if project.committee is None or (
                asf_uid not in project.committee.committee_members and asf_uid not in project.committee.committers
            ):
                raise base.ASFQuartException(
                    f"You must be a member or committer for the {project.display_name}"
                    " committee to start a release draft.",
                    errorcode=403,
                )

    async with revision.create_and_manage(project_name, version, asf_uid) as (
        _new_revision_dir,
        _new_revision_name,
    ):
        # TODO: Consider using Release.revision instead of ./latest
        async with db.session() as data:
            async with data.begin():
                # Check whether the release already exists
                if release := await data.release(project_id=project.id, version=version).get():
                    if release.phase == models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
                        raise routes.FlashError(f"A draft for {project_name} {version} already exists.")
                    else:
                        raise routes.FlashError(
                            f"A release ({release.phase.value}) for {project_name} {version} already exists."
                        )

                # Validate the version name
                # TODO: We should check that it's bigger than the current version
                if version_name_error := util.version_name_error(version):
                    raise routes.FlashError(f'Invalid version name "{version}": {version_name_error}')

                release = models.Release(
                    stage=models.ReleaseStage.RELEASE_CANDIDATE,
                    phase=models.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
                    project_id=project.id,
                    project=project,
                    version=version,
                    created=datetime.datetime.now(datetime.UTC),
                )
                data.add(release)

            await data.refresh(release)
            return release, project


@routes.committer("/draft/delete", methods=["POST"])
async def delete(session: routes.CommitterSession) -> response.Response:
    """Delete a candidate draft and all its associated files."""
    form = await DeleteForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        for _field, errors in form.errors.items():
            for error in errors:
                await quart.flash(f"{error}", "error")
        return await session.redirect(drafts)

    candidate_draft_name = form.candidate_draft_name.data
    if not candidate_draft_name:
        return await session.redirect(drafts, error="Missing required parameters")

    # Extract project name and version
    try:
        project_name, version = candidate_draft_name.rsplit("-", 1)
    except ValueError:
        return await session.redirect(drafts, error="Invalid candidate draft name format")

    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        return await session.redirect(drafts, error="You do not have access to this project")

    # Delete the metadata from the database
    async with db.session() as data:
        async with data.begin():
            try:
                await _delete_candidate_draft(data, candidate_draft_name)
            except Exception as e:
                logging.exception("Error deleting candidate draft:")
                return await session.redirect(drafts, error=f"Error deleting candidate draft: {e!s}")

    # Delete the files on disk
    draft_dir = util.get_release_candidate_draft_dir() / project_name / version
    if await aiofiles.os.path.exists(draft_dir):
        # Believe this to be another bug in mypy Protocol handling
        # TODO: Confirm that this is a bug, and report upstream
        # Changing it to str(...) doesn't work either
        # Yet it works in preview.py
        await aioshutil.rmtree(draft_dir)  # type: ignore[call-arg]

    return await session.redirect(drafts, success="Candidate draft deleted successfully")


@routes.committer("/draft/delete-file/<project_name>/<version_name>", methods=["POST"])
async def delete_file(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response:
    """Delete a specific file from the release candidate, creating a new revision."""
    form = await DeleteFileForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        return await session.redirect(evaluate, project_name=project_name, version_name=version_name)

    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

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
        return await session.redirect(evaluate, project_name=project_name, version_name=version_name)

    success_message = f"File '{rel_path_to_delete.name}' deleted successfully"
    if metadata_files_deleted:
        success_message += (
            f", and {metadata_files_deleted} associated metadata "
            f"file{'' if metadata_files_deleted == 1 else 's'} deleted"
        )
    return await session.redirect(
        evaluate, success=success_message, project_name=project_name, version_name=version_name
    )


@routes.committer("/drafts")
async def drafts(session: routes.CommitterSession) -> str:
    """Allow the user to view current candidate drafts."""
    # Do them outside of the template rendering call to ensure order
    # The user_candidate_drafts call can use cached results from user_projects
    # TODO: admin users should be able to view and manipulate all candidates if needed
    user_projects = await session.user_projects
    user_candidate_drafts = await session.user_candidate_drafts

    # Create the delete form
    delete_form = await DeleteForm.create_form()

    return await quart.render_template(
        "drafts.html",
        asf_id=session.uid,
        projects=user_projects,
        server_domain=session.host,
        number_of_release_files=util.number_of_release_files,
        candidate_drafts=user_candidate_drafts,
        delete_form=delete_form,
    )


@routes.committer("/draft/evaluate/<project_name>/<version_name>")
async def evaluate(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Evaluate all the files in the rsync upload directory for a release."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        return await session.redirect(add, error="You do not have access to this project")

    # Check that the release exists
    async with db.session() as data:
        release = await data.release(name=models.release_name(project_name, version_name), _committee=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

    if release.revision is None:
        raise base.ASFQuartException("Release does not have a revision", errorcode=404)

    base_path = util.get_release_candidate_draft_dir() / project_name / version_name / release.revision
    paths = await util.paths_recursive(base_path)
    # paths_set = set(paths)
    path_templates = {}
    path_substitutions = {}
    path_artifacts = set()
    path_metadata = set()
    path_modified = {}
    path_successes = {}
    path_warnings = {}
    path_errors = {}
    for path in paths:
        # Get template and substitutions
        elements = {
            "core": project_name,
            "version": version_name,
            "sub": None,
            "template": None,
            "substitutions": None,
        }
        template, substitutions = analysis.filename_parse(str(path), elements)
        path_templates[path] = template
        path_substitutions[path] = analysis.substitutions_format(substitutions) or "none"

        # Get artifacts and metadata
        search = re.search(analysis.extension_pattern(), str(path))
        ext_artifact = None
        ext_metadata = None
        if search:
            ext_artifact = search.group("artifact")
            # ext_metadata_artifact = search.group("metadata_artifact")
            ext_metadata = search.group("metadata")
            if ext_artifact:
                path_artifacts.add(path)
            elif ext_metadata:
                path_metadata.add(path)

        # Get modified time
        full_path = str(util.get_release_candidate_draft_dir() / project_name / version_name / release.revision / path)
        path_modified[path] = int(await aiofiles.os.path.getmtime(full_path))

        # Get successes, warnings, and errors
        path_successes[path] = await data.check_result(
            release_name=release.name, primary_rel_path=str(path), status=models.CheckResultStatus.SUCCESS
        ).all()
        path_warnings[path] = await data.check_result(
            release_name=release.name, primary_rel_path=str(path), status=models.CheckResultStatus.WARNING
        ).all()
        path_errors[path] = await data.check_result(
            release_name=release.name, primary_rel_path=str(path), status=models.CheckResultStatus.FAILURE
        ).all()

    # # TODO: This is only accurate to a second
    # oldest_check_result = None
    # latest_check_result = None
    # for path_success in path_successes:
    #     for check_result in path_successes[path_success]:
    #         if (oldest_check_result is None) or (check_result.created < oldest_check_result):
    #             oldest_check_result = check_result.created
    #         if (latest_check_result is None) or (check_result.created > latest_check_result):
    #             latest_check_result = check_result.created

    revision_name_from_link, revision_editor, revision_time = await revision.latest_info(project_name, version_name)

    # Get the number of ongoing tasks for the current revision
    ongoing_tasks_count = 0
    if revision_name_from_link:
        ongoing_tasks_count = await db.tasks_ongoing(project_name, version_name, revision_name_from_link)

    delete_file_form = await DeleteFileForm.create_form()
    return await quart.render_template(
        "draft-evaluate.html",
        asf_id=session.uid,
        project_name=project_name,
        version_name=version_name,
        release=release,
        paths=paths,
        server_domain=session.host,
        # oldest_check_result=oldest_check_result,
        # latest_check_result=latest_check_result,
        templates=path_templates,
        substitutions=path_substitutions,
        artifacts=path_artifacts,
        metadata=path_metadata,
        successes=path_successes,
        warnings=path_warnings,
        errors=path_errors,
        modified=path_modified,
        models=models,
        delete_file_form=delete_file_form,
        revision_editor=revision_editor,
        revision_time=revision_time,
        revision_name_from_link=revision_name_from_link,
        ongoing_tasks_count=ongoing_tasks_count,
    )


@routes.committer("/draft/evaluate/<project_name>/<version_name>/<path:rel_path>")
async def evaluate_path(session: routes.CommitterSession, project_name: str, version_name: str, rel_path: str) -> str:
    """Evaluate the status of all checks for a specific file."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        # Check that the release exists
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )
        if release.revision is None:
            raise base.ASFQuartException("Release does not have a revision", errorcode=404)

        # TODO: When we do more than one thing in a dir, we should use the revision directory directly
        abs_path = util.get_release_candidate_draft_dir() / project_name / version_name / release.revision / rel_path

        # Check that the file exists
        if not await aiofiles.os.path.exists(abs_path):
            raise base.ASFQuartException("File does not exist", errorcode=404)

        modified = int(await aiofiles.os.path.getmtime(abs_path))
        file_size = await aiofiles.os.path.getsize(abs_path)

        # Get all check results for this file
        query = data.check_result(release_name=release.name, primary_rel_path=str(rel_path)).order_by(
            db.validate_instrumented_attribute(models.CheckResult.checker).asc(),
            db.validate_instrumented_attribute(models.CheckResult.created).desc(),
        )
        all_results = await query.all()

        # Filter to get only the most recent result for each checker
        latest_check_results: dict[str, models.CheckResult] = {}
        for result in all_results:
            if result.checker not in latest_check_results:
                latest_check_results[result.checker] = result

        # Convert to a list for the template
        check_results_list = list(latest_check_results.values())

    file_data = {
        "filename": pathlib.Path(rel_path).name,
        "bytes_size": file_size,
        "uploaded": datetime.datetime.fromtimestamp(modified, tz=datetime.UTC),
    }

    return await quart.render_template(
        "draft-evaluate-path.html",
        project_name=project_name,
        version_name=version_name,
        rel_path=rel_path,
        package=file_data,
        release=release,
        check_results=check_results_list,
        format_file_size=routes.format_file_size,
    )


@routes.committer("/draft/hashgen/<project_name>/<version_name>/<path:file_path>", methods=["POST"])
async def hashgen(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response:
    """Generate an sha256 or sha512 hash file for a candidate draft file, creating a new revision."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

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
        return await session.redirect(evaluate, project_name=project_name, version_name=version_name)

    return await session.redirect(
        evaluate,
        success=f"{hash_type} file generated successfully",
        project_name=project_name,
        version_name=version_name,
    )


@routes.committer("/draft/overview/<project_name>/<version_name>")
async def overview(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Show an overview of the release candidate draft."""
    if not any((p.name == project_name) for p in (await session.user_projects)):
        return await session.redirect(add, error="You do not have access to this project")

    async with db.session() as data:
        release_name = models.release_name(project_name, version_name)
        release = await data.release(
            name=release_name, phase=models.ReleasePhase.RELEASE_CANDIDATE_DRAFT, _project=True
        ).demand(base.ASFQuartException("Release does not exist", errorcode=404))
        if release.revision is None:
            raise base.ASFQuartException("This release does not have a revision.", errorcode=400)

        base_path = util.get_release_candidate_draft_dir() / project_name / version_name / release.revision
        paths = await util.paths_recursive(base_path)
        path_templates = {}
        path_substitutions = {}
        path_artifacts = set()
        path_metadata = set()
        path_successes = {}
        path_warnings = {}
        path_errors = {}

        for path in paths:
            # Get template and substitutions
            elements = {
                "core": project_name,
                "version": version_name,
                "sub": None,
                "template": None,
                "substitutions": None,
            }
            template, substitutions = analysis.filename_parse(str(path), elements)
            path_templates[path] = template
            path_substitutions[path] = analysis.substitutions_format(substitutions) or "none"

            # Get artifacts and metadata
            search = re.search(analysis.extension_pattern(), str(path))
            if search:
                if search.group("artifact"):
                    path_artifacts.add(path)
                elif search.group("metadata"):
                    path_metadata.add(path)

            # Get successes, warnings, and errors
            path_successes[path] = await data.check_result(
                release_name=release.name, primary_rel_path=str(path), status=models.CheckResultStatus.SUCCESS
            ).all()
            path_warnings[path] = await data.check_result(
                release_name=release.name, primary_rel_path=str(path), status=models.CheckResultStatus.WARNING
            ).all()
            path_errors[path] = await data.check_result(
                release_name=release.name, primary_rel_path=str(path), status=models.CheckResultStatus.FAILURE
            ).all()

        revision_name_from_link, revision_editor, revision_time = await revision.latest_info(project_name, version_name)

        # Get the number of ongoing tasks for the current revision
        ongoing_tasks_count = 0
        if revision_name_from_link:
            ongoing_tasks_count = await db.tasks_ongoing(project_name, version_name, revision_name_from_link)

    delete_draft_form = await DeleteForm.create_form()
    delete_file_form = await DeleteFileForm.create_form()

    return await quart.render_template(
        "draft-overview.html",
        project_name=project_name,
        version_name=version_name,
        release=release,
        paths=paths,
        artifacts=path_artifacts,
        metadata=path_metadata,
        successes=path_successes,
        warnings=path_warnings,
        errors=path_errors,
        templates=path_templates,
        substitutions=path_substitutions,
        revision_editor=revision_editor,
        revision_time=revision_time,
        revision_name_from_link=revision_name_from_link,
        ongoing_tasks_count=ongoing_tasks_count,
        delete_form=delete_draft_form,
        delete_file_form=delete_file_form,
        asf_id=session.uid,
        server_domain=session.host,
        format_datetime=routes.format_datetime,
        models=models,
    )


@routes.committer("/draft/revision/set/<project_name>/<version_name>", methods=["POST"])
async def revision_set(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response:
    """Set a specific revision as the latest for a candidate draft."""
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    form_data = await quart.request.form
    revision_name = form_data.get("revision_name")
    if not revision_name:
        raise base.ASFQuartException("Missing revision name", errorcode=400)

    release_dir = util.get_release_candidate_draft_dir() / project_name / version_name
    target_revision_dir = release_dir / revision_name

    # Check that the target revision directory exists
    if not await aiofiles.os.path.isdir(target_revision_dir):
        raise base.ASFQuartException("Target revision directory not found", errorcode=404)

    try:
        # Target must be relative for the symlink
        # TODO: We should probably log who is doing this, to create an audit trail
        async with db.session() as data:
            release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
                base.ASFQuartException("Release does not exist", errorcode=404)
            )
            release.revision = revision_name
            await data.commit()
    except Exception as e:
        logging.exception("Error setting revision:")
        return await session.redirect(
            revisions,
            error=f"Failed to set revision {revision_name} as latest: {e!s}",
            project_name=project_name,
            version_name=version_name,
        )

    return await session.redirect(
        revisions,
        success=f"Revision {revision_name} set as latest",
        project_name=project_name,
        version_name=version_name,
    )


@routes.committer("/draft/revisions/<project_name>/<version_name>")
async def revisions(session: routes.CommitterSession, project_name: str, version_name: str) -> str:
    """Show the revision history for a release candidate draft."""
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )
        if release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
            raise base.ASFQuartException("Revisions are only available for candidate drafts", errorcode=400)

        release_dir = util.get_release_candidate_draft_dir() / project_name / version_name
        revision_dirs: list[str] = []
        with contextlib.suppress(FileNotFoundError):
            for entry in await aiofiles.os.listdir(str(release_dir)):
                # Match pattern like "user@YYYY-MM-DDTHH.MM.SS.fffZ"
                if "@" in entry and entry.endswith("Z"):
                    if await aiofiles.os.path.isdir(release_dir / entry):
                        revision_dirs.append(entry)

        # Sort revisions by timestamp
        def sort_key(rev_name: str) -> datetime.datetime:
            try:
                # Remove trailing Z, though we could just put it in the template pattern
                timestamp_str = rev_name.split("@", 1)[1][:-1]
                return datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H.%M.%S.%f")
            except (IndexError, ValueError):
                # Should not happen for valid names, put invalid ones last
                return datetime.datetime.min

        # Sort revisions by timestamp, newest first
        revision_dirs.sort(key=sort_key, reverse=True)

        # Get parent links using a direct query due to the use of in_(...)
        query = sqlmodel.select(models.TextValue).where(
            models.TextValue.ns == "draft_parent",
            db.validate_instrumented_attribute(models.TextValue.key).in_(revision_dirs),
        )
        parent_links_result = await data.execute(query)
        parent_map = {link.key: link.value for link in parent_links_result.scalars().all()}

        # Determine the current latest revision
        latest_revision_name = release.revision

        revision_history = []
        prev_revision_files: set[pathlib.Path] | None = None
        prev_revision_name: str | None = None

        # Oldest to newest, to build diffs relative to previous revision
        for rev_name in reversed(revision_dirs):
            revision_data, current_revision_files = await _revisions_process(
                rev_name,
                release_dir,
                parent_map,
                prev_revision_files,
                prev_revision_name,
                sort_key,
            )
            revision_history.append(revision_data)
            prev_revision_files = current_revision_files
            prev_revision_name = rev_name

    return await quart.render_template(
        "draft-revisions.html",
        project_name=project_name,
        version_name=version_name,
        release=release,
        revision_history=list(reversed(revision_history)),
        latest_revision_name=latest_revision_name,
    )


@routes.committer("/draft/sbomgen/<project_name>/<version_name>/<path:file_path>", methods=["POST"])
async def sbomgen(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response:
    """Generate a CycloneDX SBOM file for a candidate draft file, creating a new revision."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

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
                release = await data.release(
                    name=models.release_name(project_name, version_name), _project=True
                ).demand(base.ASFQuartException("Release does not exist", errorcode=404))

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
        return await session.redirect(evaluate, project_name=project_name, version_name=version_name)

    return await session.redirect(
        evaluate,
        success=f"SBOM generation task queued for {rel_path.name}",
        project_name=project_name,
        version_name=version_name,
    )


@routes.committer("/draft/svnload/<project_name>/<version_name>", methods=["POST"])
async def svnload(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Import files from SVN into a draft."""

    form = await SvnImportForm.create_form()

    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        release = await data.release(name=models.release_name(project_name, version_name)).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )
        if release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
            raise base.ASFQuartException("SVN import is only available for candidate drafts", errorcode=400)

    if not await form.validate_on_submit():
        for _field, errors in form.errors.items():
            for error in errors:
                await quart.flash(f"{error}", "error")
        return await session.redirect(
            add_files,
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
            add_files,
            error="Error queueing SVN import task",
            project_name=project_name,
            version_name=version_name,
        )

    return await session.redirect(
        evaluate,
        success="SVN import task queued successfully",
        project_name=project_name,
        version_name=version_name,
    )


@routes.committer("/draft/tools/<project_name>/<version_name>/<path:file_path>")
async def tools(session: routes.CommitterSession, project_name: str, version_name: str, file_path: str) -> str:
    """Show the tools for a specific file."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        # Check that the release exists
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )
        if release.revision is None:
            raise base.ASFQuartException("Release does not have a revision", errorcode=404)

        full_path = str(
            util.get_release_candidate_draft_dir() / project_name / version_name / release.revision / file_path
        )

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
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        return await session.redirect(add, error="You do not have access to this project")

    # Check that the release exists
    async with db.session() as data:
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

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


@routes.committer("/draft/view/<project_name>/<version_name>/<path:file_path>")
async def view_path(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response | str:
    """View the content of a specific file in the release candidate draft."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        return await session.redirect(
            view, error="You do not have access to this project", project_name=project_name, version_name=version_name
        )

    async with db.session() as data:
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )
        if release.revision is None:
            raise base.ASFQuartException("Release does not have a revision", errorcode=404)

    # Limit to 256 KiB
    _max_view_size = 256 * 1024
    full_path = util.get_release_candidate_draft_dir() / project_name / version_name / release.revision / file_path

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
        return await session.redirect(drafts, error="Invalid form data")

    body = await mail.generate_preview(
        util.unwrap(form.body.data), util.unwrap(form.asfuid.data), util.unwrap(form.vote_duration.data)
    )
    return quart.Response(body, mimetype="text/plain")


@routes.committer("/draft/vote/start/<project_name>/<version>/<revision>", methods=["GET", "POST"])
async def vote_start(
    session: routes.CommitterSession, project_name: str, version: str, revision: str
) -> response.Response | str:
    """Show the vote initiation form for a release."""
    async with db.session() as data:
        project = await data.project(name=project_name).demand(routes.FlashError("Project not found"))
        release = await data.release(project_id=project.id, version=version, _committee=True).demand(
            routes.FlashError("Release candidate not found")
        )
        # Check that the user is on the project committee for the release
        # TODO: Consider relaxing this to all committers
        # Otherwise we must not show the vote form
        if not user.is_committee_member(release.committee, session.uid):
            return await session.redirect(overview, error="You must be on the PMC of this project to start a vote")
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
                    return await session.redirect(drafts, error=error)

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
            resolve: routes.RouteHandler[str] = candidate.resolve  # type: ignore[has-type]
            return await session.redirect(
                resolve,
                success=f"The vote announcement email will soon be sent to {email_to}.",
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
    release = await data.release(name=candidate_draft_name, _project=True, _packages=True).get()
    if not release:
        raise routes.FlashError("Candidate draft not found")
    if release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
        raise routes.FlashError("Candidate draft is not in the release candidate draft phase")

    # Delete all associated packages first
    for package in release.packages:
        await data.delete(package)

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
    release = await data.release(name=candidate_draft_name, _project=True).demand(
        routes.FlashError("Candidate draft not found")
    )

    # Verify that it's in the correct phase
    if release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
        return "This release is not in the candidate draft phase"

    base_dir = util.get_release_candidate_draft_dir() / project_name / version_name
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
    target_dir = util.get_release_candidate_dir() / project_name / version_name

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


async def _revisions_process(
    rev_name: str,
    release_dir: pathlib.Path,
    parent_map: dict[str, str],
    prev_revision_files: set[pathlib.Path] | None,
    prev_revision_name: str | None,
    sort_key: Callable[[str], datetime.datetime],
) -> tuple[dict, set[pathlib.Path]]:
    """Process a single revision and calculate its diff from the previous."""
    current_revision_dir = release_dir / rev_name
    current_revision_files = set(await util.paths_recursive(current_revision_dir))
    parent_name = parent_map.get(rev_name)

    added_files: set[pathlib.Path] = set()
    removed_files: set[pathlib.Path] = set()
    modified_files: set[pathlib.Path] = set()

    if (prev_revision_files is not None) and (prev_revision_name is not None):
        added_files = current_revision_files - prev_revision_files
        removed_files = prev_revision_files - current_revision_files
        common_files = current_revision_files & prev_revision_files

        # Check modification times for common files
        parent_revision_dir = release_dir / prev_revision_name
        mtime_tasks = []
        for common_file in common_files:

            async def check_mtime(file_path: pathlib.Path) -> tuple[pathlib.Path, bool]:
                try:
                    parent_mtime = await aiofiles.os.path.getmtime(parent_revision_dir / file_path)
                    current_mtime = await aiofiles.os.path.getmtime(current_revision_dir / file_path)
                    return file_path, parent_mtime != current_mtime
                except OSError:
                    # Treat errors as modified
                    return file_path, True

            mtime_tasks.append(check_mtime(common_file))

        results = await asyncio.gather(*mtime_tasks)
        modified_files = {f for f, modified in results if modified}
    else:
        # First revision, all files are considered added
        added_files = current_revision_files

    try:
        editor = rev_name.split("@", 1)[0]
        timestamp = sort_key(rev_name)
    except (ValueError, IndexError):
        editor = "Unknown"
        timestamp = None

    revision_data = {
        "name": rev_name,
        "editor": editor,
        "timestamp": timestamp,
        "parent": parent_name,
        "added": sorted(list(added_files)),
        "removed": sorted(list(removed_files)),
        "modified": sorted(list(modified_files)),
    }
    return revision_data, current_revision_files


async def _save_file(file: datastructures.FileStorage, target_path: pathlib.Path) -> None:
    async with aiofiles.open(target_path, "wb") as f:
        while chunk := await asyncio.to_thread(file.stream.read, 8192):
            await f.write(chunk)


async def _upload_files(
    project_name: str,
    version_name: str,
    asf_uid: str,
    file_name: pathlib.Path | None,
    files: Sequence[datastructures.FileStorage],
) -> int:
    """Process and save the uploaded files into a new draft revision."""
    async with revision.create_and_manage(project_name, version_name, asf_uid) as (
        new_revision_dir,
        _new_revision_name,
    ):

        def get_target_path(file: datastructures.FileStorage) -> pathlib.Path:
            # Determine the target path within the new revision directory
            relative_file_path: pathlib.Path
            if not file_name:
                if not file.filename:
                    raise routes.FlashError("No filename provided")
                # Use the original name
                relative_file_path = pathlib.Path(file.filename)
            else:
                # Use the provided name, relative to its anchor
                # In other words, ignore the leading "/"
                relative_file_path = file_name.relative_to(file_name.anchor)

            # Construct path inside the new revision directory
            target_path = new_revision_dir / relative_file_path
            return target_path

        # Save each uploaded file to the new revision directory
        for file in files:
            target_path = get_target_path(file)
            # Ensure parent directories exist within the new revision
            target_path.parent.mkdir(parents=True, exist_ok=True)
            await _save_file(file, target_path)

    return len(files)
