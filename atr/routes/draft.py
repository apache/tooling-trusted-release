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
import re
from typing import TYPE_CHECKING, Protocol, TypeVar

import aiofiles.os
import aioshutil
import asfquart.base as base
import quart
import wtforms

import atr.analysis as analysis
import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.tasks as tasks
import atr.tasks.sbom as sbom
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import Sequence

    import werkzeug.datastructures as datastructures
    import werkzeug.wrappers.response as response

# _CONFIG: Final = config.get()
# _LOGGER: Final = logging.getLogger(__name__)


T = TypeVar("T")


class AddProtocol(Protocol):
    """Protocol for forms that create release candidate drafts."""

    version_name: wtforms.StringField
    project_name: wtforms.SelectField
    project_label_suffix: wtforms.StringField


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


class DeleteFileForm(util.QuartFormTyped):
    """Form for deleting a file."""

    file_path = wtforms.StringField("File path", validators=[wtforms.validators.InputRequired("File path is required")])
    submit = wtforms.SubmitField("Delete file")


class PromoteForm(util.QuartFormTyped):
    """Form for promoting a candidate draft."""

    candidate_draft_name = wtforms.StringField(
        "Candidate draft name", validators=[wtforms.validators.InputRequired("Candidate draft name is required")]
    )
    confirm_promote = wtforms.BooleanField(
        "Confirmation", validators=[wtforms.validators.DataRequired("You must confirm to proceed with promotion")]
    )
    target_phase = wtforms.RadioField(
        "Target phase",
        choices=[
            (models.ReleasePhase.RELEASE_CANDIDATE_BEFORE_VOTE.value, "Release candidate (before vote) - RECOMMENDED"),
            (models.ReleasePhase.RELEASE_PREVIEW.value, "Release preview"),
            (models.ReleasePhase.RELEASE_AFTER_ANNOUNCEMENT.value, "Release (after announcement)"),
        ],
        default=models.ReleasePhase.RELEASE_CANDIDATE_BEFORE_VOTE.value,
        validators=[wtforms.validators.InputRequired("Target phase selection is required")],
    )
    submit = wtforms.SubmitField("Promote candidate draft")


async def _number_of_release_files(release: models.Release) -> int:
    """Return the number of files in the release."""
    path_project = release.project.name
    path_version = release.version
    path = util.get_release_candidate_draft_dir() / path_project / path_version
    return len(await util.paths_recursive(path))


@routes.committer("/draft/add", methods=["GET", "POST"])
async def add(session: routes.CommitterSession) -> response.Response | str:
    """Show a page to allow the user to rsync files to candidate drafts."""
    # Do them outside of the template rendering call to ensure order
    # The user_candidate_drafts call can use cached results from user_projects
    user_projects = await session.user_projects
    user_candidate_drafts = await session.user_candidate_drafts

    class AddForm(util.QuartFormTyped):
        project_name = wtforms.SelectField("Project", choices=[(p.name, p.full_name or p.name) for p in user_projects])
        version_name = wtforms.StringField(
            "Version", validators=[wtforms.validators.InputRequired("Version is required")]
        )
        project_label_suffix = wtforms.StringField(
            "Project label suffix",
            validators=[
                wtforms.validators.Optional(),
                wtforms.validators.Regexp(
                    r"^[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*$",
                    message="Suffix must contain only alphanumeric characters and hyphens, "
                    "and cannot start or end with a hyphen.",
                ),
            ],
        )
        submit = wtforms.SubmitField("Create candidate draft")

    form = await AddForm.create_form()
    if quart.request.method == "POST":
        if not await form.validate_on_submit():
            # TODO: Show the form with errors
            return await session.redirect(add, error="Invalid form data")
        await _add(session, form)
        return await session.redirect(directory, success="Release candidate created successfully")

    return await quart.render_template(
        "draft-add.html",
        asf_id=session.uid,
        projects=user_projects,
        server_domain=session.host,
        number_of_release_files=_number_of_release_files,
        candidate_drafts=user_candidate_drafts,
        user_projects=user_projects,
        form=form,
    )


@routes.committer("/draft/add/<project_name>/<version_name>", methods=["GET", "POST"])
async def add_file(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
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

            number_of_files = await _upload_files(project_name, version_name, file_name, file_data)
            return await session.redirect(
                review,
                success=f"{number_of_files} file{'' if number_of_files == 1 else 's'} added successfully",
                project_name=project_name,
                version_name=version_name,
            )
        except Exception as e:
            logging.exception("Error adding file:")
            await quart.flash(f"Error adding file: {e!s}", "error")

    return await quart.render_template(
        "draft-add-files.html",
        asf_id=session.uid,
        server_domain=session.host,
        project_name=project_name,
        version_name=version_name,
        form=form,
    )


@routes.committer("/draft/delete", methods=["POST"])
async def delete(session: routes.CommitterSession) -> response.Response:
    """Delete a candidate draft and all its associated files."""
    form = await DeleteForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        for _field, errors in form.errors.items():
            for error in errors:
                await quart.flash(f"{error}", "error")
        return await session.redirect(directory)

    candidate_draft_name = form.candidate_draft_name.data
    if not candidate_draft_name:
        return await session.redirect(promote, error="Missing required parameters")

    # Extract project name and version
    try:
        project_name, version = candidate_draft_name.rsplit("-", 1)
    except ValueError:
        return await session.redirect(promote, error="Invalid candidate draft name format")

    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        return await session.redirect(promote, error="You do not have access to this project")

    # Delete the metadata from the database
    async with db.session() as data:
        async with data.begin():
            try:
                await _delete_candidate_draft(data, candidate_draft_name)
            except Exception as e:
                logging.exception("Error deleting candidate draft:")
                return await session.redirect(promote, error=f"Error deleting candidate draft: {e!s}")

    # Delete the files on disk
    draft_dir = util.get_release_candidate_draft_dir() / project_name / version
    if await aiofiles.os.path.exists(draft_dir):
        # Believe this to be another bug in mypy Protocol handling
        # TODO: Confirm that this is a bug, and report upstream
        # Changing it to str(...) doesn't work either
        # Yet it works in preview.py
        await aioshutil.rmtree(draft_dir)  # type: ignore[call-arg]

    return await session.redirect(directory, success="Candidate draft deleted successfully")


@routes.committer("/draft/delete-file/<project_name>/<version_name>", methods=["POST"])
async def delete_file(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response:
    """Delete a specific file from the release candidate."""
    form = await DeleteFileForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        return await session.redirect(review, project_name=project_name, version_name=version_name)

    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        # Check that the release exists
        await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

        file_path = str(form.file_path.data)
        full_path_obj = util.get_release_candidate_draft_dir() / project_name / version_name / file_path
        full_path = str(full_path_obj)

        # Check that the file exists
        if not await aiofiles.os.path.exists(full_path):
            raise base.ASFQuartException("File does not exist", errorcode=404)

        # Check whether the file is an artifact
        metadata_files = 0
        if analysis.is_artifact(full_path_obj):
            # If so, delete all associated metadata files
            for p in await util.paths_recursive(full_path_obj.parent):
                if p.name.startswith(full_path_obj.name + "."):
                    await aiofiles.os.remove(full_path_obj.parent / p.name)
                    metadata_files += 1

        # Delete the file
        await aiofiles.os.remove(full_path)

        # Ensure that checks are queued again
        await tasks.draft_checks(project_name, version_name, caller_data=data)
        await data.commit()

    success_message = "File deleted successfully"
    if metadata_files:
        success_message += (
            f", and {metadata_files} associated metadata file{'' if metadata_files == 1 else 's'} deleted"
        )
    return await session.redirect(review, success=success_message, project_name=project_name, version_name=version_name)


@routes.committer("/draft/hashgen/<project_name>/<version_name>/<path:file_path>", methods=["POST"])
async def hashgen(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response:
    """Generate an sha256 or sha512 hash file for a candidate draft file."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        # Check that the release exists
        await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

        # Get the hash type from the form data
        # This is just a button, so we don't make a whole form validation schema for it
        form = await quart.request.form
        hash_type = form.get("hash_type")
        if hash_type not in {"sha256", "sha512"}:
            raise base.ASFQuartException("Invalid hash type", errorcode=400)

        # Construct paths
        base_path = util.get_release_candidate_draft_dir() / project_name / version_name
        full_path = base_path / file_path
        hash_path = file_path + f".{hash_type}"
        full_hash_path = base_path / hash_path

        # Check that the source file exists
        if not await aiofiles.os.path.exists(full_path):
            raise base.ASFQuartException("Source file does not exist", errorcode=404)

        # Check that the hash file does not already exist
        if await aiofiles.os.path.exists(full_hash_path):
            raise base.ASFQuartException(f"{hash_type} file already exists", errorcode=400)

        # Read the file and compute the hash
        hash_obj = hashlib.sha256() if hash_type == "sha256" else hashlib.sha512()
        async with aiofiles.open(full_path, "rb") as f:
            while chunk := await f.read(8192):
                hash_obj.update(chunk)

        # Write the hash file
        hash_value = hash_obj.hexdigest()
        async with aiofiles.open(full_hash_path, "w") as f:
            await f.write(f"{hash_value}  {file_path}\n")

        # Ensure that checks are queued again
        await tasks.draft_checks(project_name, version_name, caller_data=data)
        await data.commit()

    return await session.redirect(
        review, success=f"{hash_type} file generated successfully", project_name=project_name, version_name=version_name
    )


@routes.committer("/drafts")
async def directory(session: routes.CommitterSession) -> str:
    """Allow the user to view current candidate drafts."""
    # Do them outside of the template rendering call to ensure order
    # The user_candidate_drafts call can use cached results from user_projects
    # TODO: admin users should be able to view and manipulate all candidates if needed
    user_projects = await session.user_projects
    user_candidate_drafts = await session.user_candidate_drafts

    # Create the delete form
    delete_form = await DeleteForm.create_form()

    return await quart.render_template(
        "draft-directory.html",
        asf_id=session.uid,
        projects=user_projects,
        server_domain=session.host,
        number_of_release_files=_number_of_release_files,
        candidate_drafts=user_candidate_drafts,
        delete_form=delete_form,
    )


@routes.committer("/draft/promote", methods=["GET", "POST"])
async def promote(session: routes.CommitterSession) -> str | response.Response:
    """Allow the user to promote a candidate draft."""
    user_candidate_drafts = await session.user_candidate_drafts

    # Create the forms
    promote_form = await PromoteForm.create_form(
        data=await quart.request.form if (quart.request.method == "POST") else None
    )
    delete_form = await DeleteForm.create_form()

    if (quart.request.method == "POST") and (await promote_form.validate_on_submit()):
        candidate_draft_name = promote_form.candidate_draft_name.data
        if not candidate_draft_name:
            return await session.redirect(promote, error="Missing required parameters")

        # Extract project name and version
        try:
            project_name, version_name = candidate_draft_name.rsplit("-", 1)
        except ValueError:
            return await session.redirect(promote, error="Invalid candidate draft name format")

        # Check that the user has access to the project
        if not any((p.name == project_name) for p in (await session.user_projects)):
            return await session.redirect(promote, error="You do not have access to this project")

        selected_target_phase_value = promote_form.target_phase.data
        try:
            target_phase_enum = models.ReleasePhase(selected_target_phase_value)
        except ValueError:
            return await session.redirect(promote, error="Invalid target phase selected")

        async with db.session() as data:
            try:
                return await _promote(
                    data, candidate_draft_name, session, target_phase_enum, project_name, version_name
                )
            except Exception as e:
                logging.exception("Error promoting candidate draft:")
                return await session.redirect(promote, error=f"Error promoting candidate draft: {e!s}")

    return await quart.render_template(
        "draft-promote.html",
        candidate_drafts=user_candidate_drafts,
        promote_form=promote_form,
        delete_form=delete_form,
    )


@routes.committer("/draft/review/<project_name>/<version_name>")
async def review(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Show all the files in the rsync upload directory for a release."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        return await session.redirect(add, error="You do not have access to this project")

    # Check that the release exists
    async with db.session() as data:
        release = await data.release(name=models.release_name(project_name, version_name), _committee=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

    base_path = util.get_release_candidate_draft_dir() / project_name / version_name
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
        full_path = str(util.get_release_candidate_draft_dir() / project_name / version_name / path)
        path_modified[path] = int(await aiofiles.os.path.getmtime(full_path))

        # Get successes, warnings, and errors
        path_successes[path] = await data.check_result(
            release_name=release.name, path=str(path), status=models.CheckResultStatus.SUCCESS
        ).all()
        path_warnings[path] = await data.check_result(
            release_name=release.name, path=str(path), status=models.CheckResultStatus.WARNING
        ).all()
        path_errors[path] = await data.check_result(
            release_name=release.name, path=str(path), status=models.CheckResultStatus.FAILURE
        ).all()

    delete_file_form = await DeleteFileForm.create_form()

    return await quart.render_template(
        "draft-review.html",
        asf_id=session.uid,
        project_name=project_name,
        version_name=version_name,
        release=release,
        paths=paths,
        server_domain=session.host,
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
    )


@routes.committer("/draft/review/<project_name>/<version_name>/<path:file_path>")
async def review_path(session: routes.CommitterSession, project_name: str, version_name: str, file_path: str) -> str:
    """Show the status of all checks for a specific file."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        # Check that the release exists
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

        full_path = str(util.get_release_candidate_draft_dir() / project_name / version_name / file_path)

        # Check that the file exists
        if not await aiofiles.os.path.exists(full_path):
            raise base.ASFQuartException("File does not exist", errorcode=404)

        modified = int(await aiofiles.os.path.getmtime(full_path))
        file_size = await aiofiles.os.path.getsize(full_path)

        # Get all check results for this file
        query = data.check_result(release_name=release.name, path=file_path).order_by(
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
        "filename": pathlib.Path(file_path).name,
        "bytes_size": file_size,
        "uploaded": datetime.datetime.fromtimestamp(modified, tz=datetime.UTC),
    }

    return await quart.render_template(
        "draft-review-path.html",
        project_name=project_name,
        version_name=version_name,
        file_path=file_path,
        package=file_data,
        release=release,
        check_results=check_results_list,
        format_file_size=routes.format_file_size,
    )


@routes.committer("/draft/sbomgen/<project_name>/<version_name>/<path:file_path>", methods=["POST"])
async def sbomgen(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response:
    """Generate a CycloneDX SBOM file for a candidate draft file."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        # Check that the release exists
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

        # Construct paths
        base_path = util.get_release_candidate_draft_dir() / project_name / version_name
        full_path = base_path / file_path
        # Standard CycloneDX extension
        sbom_path_rel = file_path + ".cdx.json"
        full_sbom_path = base_path / sbom_path_rel

        # Check that the source file exists
        if not await aiofiles.os.path.exists(full_path):
            raise base.ASFQuartException("Source artifact file does not exist", errorcode=404)

        # Check that the file is a .tar.gz archive
        if not file_path.endswith(".tar.gz"):
            raise base.ASFQuartException("SBOM generation is only supported for .tar.gz files", errorcode=400)

        # Check that the SBOM file does not already exist
        if await aiofiles.os.path.exists(full_sbom_path):
            raise base.ASFQuartException("SBOM file already exists", errorcode=400)

        # Create and queue the task
        sbom_task = models.Task(
            task_type=models.TaskType.SBOM_GENERATE_CYCLONEDX,
            task_args=sbom.GenerateCycloneDX(
                artifact_path=str(full_path),
                output_path=str(full_sbom_path),
            ).model_dump(),
            added=datetime.datetime.now(datetime.UTC),
            status=models.TaskStatus.QUEUED,
            release_name=release.name,
        )
        data.add(sbom_task)
        await data.commit()

    return await session.redirect(
        review,
        success=f"SBOM generation task queued for {pathlib.Path(file_path).name}",
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

        full_path = str(util.get_release_candidate_draft_dir() / project_name / version_name / file_path)

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
        user_is_admin=session.user_is_admin,
    )


@routes.committer("/draft/viewer/<project_name>/<version_name>")
async def viewer(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Show all the files in the rsync upload directory for a release."""
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
        stat async for stat in util.content_list(util.get_release_candidate_draft_dir(), project_name, version_name)
    ]

    return await quart.render_template(
        "phase-viewer.html",
        file_stats=file_stats,
        release=release,
        format_datetime=routes.format_datetime,
        format_file_size=routes.format_file_size,
        format_permissions=routes.format_permissions,
        phase="release candidate draft",
        phase_key="draft",
    )


@routes.committer("/draft/viewer/<project_name>/<version_name>/<path:file_path>")
async def viewer_path(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response | str:
    """Show the content of a specific file in the release candidate draft."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        return await session.redirect(
            viewer, error="You do not have access to this project", project_name=project_name, version_name=version_name
        )

    async with db.session() as data:
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

    _max_view_size = 1 * 1024 * 1024
    full_path = util.get_release_candidate_draft_dir() / project_name / version_name / file_path
    content, is_text, is_truncated, error_message = await util.read_file_for_viewer(full_path, _max_view_size)
    return await quart.render_template(
        "phase-viewer-path.html",
        release=release,
        project_name=project_name,
        version_name=version_name,
        file_path=file_path,
        content=content,
        is_text=is_text,
        is_truncated=is_truncated,
        error_message=error_message,
        format_file_size=routes.format_file_size,
        phase_key="draft",
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


async def _add(session: routes.CommitterSession, form: AddProtocol) -> None:
    """Handle POST request for creating a new release candidate draft."""
    version = str(form.version_name.data)
    base_project_name = str(form.project_name.data)
    suffix = str(form.project_label_suffix.data or "")

    # Create the release record in the database
    async with db.session() as data:
        async with data.begin():
            project = await data.project(name=base_project_name).get()
            if not project:
                raise routes.FlashError("Base project not found")

            if base_project_name not in (p.name for p in await session.user_projects):
                raise routes.FlashError(
                    f"You must be a participant of {base_project_name} to submit a release candidate",
                )

            # Construct the final label
            final_project_label = base_project_name
            if suffix:
                final_project_label += f"-{suffix}"

            # Check whether the subproject already exists
            if final_project_label != base_project_name:
                sub_project = await data.project(name=final_project_label).get()
                if sub_project is not None:
                    project = sub_project
                else:
                    # Create the new subproject
                    # TODO: We're letting any participant do this
                    # But we should probably limit this to committee members
                    project = models.Project(
                        name=final_project_label,
                        full_name=f"{project.full_name} {suffix.title()}",
                        is_podling=project.is_podling,
                        is_retired=project.is_retired,
                        description=project.description,
                        category=project.category,
                        programming_languages=project.programming_languages,
                        committee_id=project.committee_id,
                        vote_policy_id=project.vote_policy_id,
                        # TODO: Add "created" and "created_by" to models.Project
                        # created=datetime.datetime.now(datetime.UTC),
                        # created_by=session.uid,
                    )
                    data.add(project)

    async with db.session() as data:
        async with data.begin():
            if release := await data.release(project_id=project.id, version=version).get():
                raise routes.FlashError(f"{release.phase.value.upper()} with this name already exists")

            # Release is now linked to the appropriate project or subproject
            release = models.Release(
                stage=models.ReleaseStage.RELEASE_CANDIDATE,
                phase=models.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
                project_id=project.id,
                project=project,
                version=version,
                created=datetime.datetime.now(datetime.UTC),
            )
            data.add(release)


async def _promote(
    data: db.Session,
    candidate_draft_name: str,
    session: routes.CommitterSession,
    target_phase_enum: models.ReleasePhase,
    project_name: str,
    version_name: str,
) -> str | response.Response:
    # Get the release
    release = await data.release(name=candidate_draft_name, _project=True).demand(
        routes.FlashError("Candidate draft not found")
    )

    # Verify that it's in the correct phase
    if release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
        return await session.redirect(promote, error="This release is not in the candidate draft phase")

    source_dir = util.get_release_candidate_draft_dir() / project_name / version_name
    target_dir: pathlib.Path
    success_message: str

    # Promote it to the target phase
    # TODO: Obtain a lock for this
    if target_phase_enum == models.ReleasePhase.RELEASE_CANDIDATE_BEFORE_VOTE:
        release.stage = models.ReleaseStage.RELEASE_CANDIDATE
        release.phase = models.ReleasePhase.RELEASE_CANDIDATE_BEFORE_VOTE
        target_dir = util.get_release_candidate_dir() / project_name / version_name
        success_message = "Candidate draft successfully promoted to candidate (before vote)"
    elif target_phase_enum == models.ReleasePhase.RELEASE_PREVIEW:
        release.stage = models.ReleaseStage.RELEASE
        release.phase = models.ReleasePhase.RELEASE_PREVIEW
        target_dir = util.get_release_preview_dir() / project_name / version_name
        success_message = "Candidate draft successfully promoted to release preview"
    elif target_phase_enum == models.ReleasePhase.RELEASE_AFTER_ANNOUNCEMENT:
        release.stage = models.ReleaseStage.RELEASE
        release.phase = models.ReleasePhase.RELEASE_AFTER_ANNOUNCEMENT
        target_dir = util.get_release_dir() / project_name / version_name
        success_message = "Candidate draft successfully promoted to release (after announcement)"
    else:
        # Should not happen due to form validation
        return await session.redirect(promote, error="Unsupported target phase")

    if await aiofiles.os.path.exists(target_dir):
        return await session.redirect(promote, error=f"Target directory {target_dir.name} already exists")

    await data.commit()
    await aioshutil.move(str(source_dir), str(target_dir))

    return await session.redirect(promote, success=success_message)


async def _upload_files(
    project_name: str,
    version_name: str,
    file_name: pathlib.Path | None,
    files: Sequence[datastructures.FileStorage],
) -> int:
    """Process and save the uploaded files."""
    # Create target directory
    target_dir = util.get_release_candidate_draft_dir() / project_name / version_name
    target_dir.mkdir(parents=True, exist_ok=True)

    def get_filepath(file: datastructures.FileStorage) -> pathlib.Path:
        # Use the original filename if no path is specified
        if not file_name:
            if not file.filename:
                raise routes.FlashError("No filename provided")
            return pathlib.Path(file.filename)
        else:
            return file_name

    for file in files:
        # Save file to specified path
        file_path = get_filepath(file)
        target_path = target_dir / file_path.relative_to(file_path.anchor)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        await _save_file(file, target_path)

    # Ensure that checks are queued again
    await tasks.draft_checks(project_name, version_name)

    return len(files)


async def _save_file(file: datastructures.FileStorage, target_path: pathlib.Path) -> None:
    async with aiofiles.open(target_path, "wb") as f:
        while chunk := await asyncio.to_thread(file.stream.read, 8192):
            await f.write(chunk)
