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


async def _number_of_release_files(release: models.Release) -> int:
    """Return the number of files in the release."""
    path_project = release.project.name
    path_version = release.version
    path = util.get_release_candidate_draft_dir() / path_project / path_version
    return len(await util.paths_recursive(path))


def _path_warnings_errors(
    paths: set[pathlib.Path], path: pathlib.Path, ext_artifact: str | None, ext_metadata: str | None
) -> tuple[list[str], list[str]]:
    # NOTE: This is important institutional logic
    # TODO: We should probably move this to somewhere more important than a routes module
    warnings = []
    errors = []

    # The Release Distribution Policy specifically allows README and CHANGES, etc.
    # We assume that LICENSE and NOTICE are permitted also
    if path.name == "KEYS":
        errors.append("Please upload KEYS to ATR directly instead of using rsync")
    elif any(part.startswith(".") for part in path.parts):
        # TODO: There is not a a policy for this
        # We should enquire as to whether such a policy should be instituted
        # We're forbidding dotfiles to catch accidental uploads of e.g. .git or .htaccess
        # Such cases are likely to be in error, and could carry security risks
        errors.append("Dotfiles are forbidden")

    if ext_artifact:
        updated_warnings, updated_errors = _path_warnings_errors_artifact(paths, path, ext_artifact)
        warnings.extend(updated_warnings)
        errors.extend(updated_errors)

    if ext_metadata:
        updated_warnings, updated_errors = _path_warnings_errors_metadata(paths, path, ext_metadata)
        warnings.extend(updated_warnings)
        errors.extend(updated_errors)

    return warnings, errors


def _path_warnings_errors_artifact(
    paths: set[pathlib.Path], path: pathlib.Path, ext_artifact: str
) -> tuple[list[str], list[str]]:
    # We refer to the following authoritative policies:
    # - Release Creation Process (RCP)
    # - Release Distribution Policy (RDP)

    warnings: list[str] = []
    errors: list[str] = []

    # RDP says that .asc is required and one of .sha256 or .sha512
    if path.with_suffix(path.suffix + ".asc") not in paths:
        errors.append("Missing an .asc counterpart")
    no_sha256 = path.with_suffix(path.suffix + ".sha256") not in paths
    no_sha512 = path.with_suffix(path.suffix + ".sha512") not in paths
    if no_sha256 and no_sha512:
        errors.append("Missing a .sha256 or .sha512 counterpart")

    return warnings, errors


def _path_warnings_errors_metadata(
    paths: set[pathlib.Path], path: pathlib.Path, ext_metadata: str
) -> tuple[list[str], list[str]]:
    # We refer to the following authoritative policies:
    # - Release Creation Process (RCP)
    # - Release Distribution Policy (RDP)

    warnings: list[str] = []
    errors: list[str] = []
    suffixes = set(path.suffixes)

    if ".md5" in suffixes:
        # Forbidden by RCP, deprecated by RDP
        errors.append("The use of .md5 is forbidden, please use .sha512")
    if ".sha1" in suffixes:
        # Deprecated by RDP
        warnings.append("The use of .sha1 is deprecated, please use .sha512")
    if ".sha" in suffixes:
        # Discouraged by RDP
        warnings.append("The use of .sha is discouraged, please use .sha512")
    if ".sig" in suffixes:
        # Forbidden by RCP, forbidden by RDP
        errors.append("Binary signature files are forbidden, please use .asc")

    # "Signature and checksum files for verifying distributed artifacts should
    # not be provided, unless named as indicated above." (RDP)
    # Also .mds is allowed, but we'll ignore that for now
    # TODO: Is .mds supported in analysis.METADATA_SUFFIXES?
    if ext_metadata not in {".asc", ".sha256", ".sha512", ".md5", ".sha", ".sha1"}:
        warnings.append("The use of this metadata file is discouraged")

    # If a metadata file is present, it must have an artifact counterpart
    artifact_path = path.with_name(path.name.removesuffix(ext_metadata))
    if artifact_path not in paths:
        errors.append("Missing an artifact counterpart")

    return warnings, errors


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
    """Show a page to allow the user to add a single file to a candidate draft."""

    class AddFilesForm(util.QuartFormTyped):
        """Form for adding file(s) to a release candidate."""

        file_name = wtforms.StringField("File name (optional)")
        file_data = wtforms.MultipleFileField(
            "File(s)", validators=[wtforms.validators.InputRequired("File(s) are required")]
        )
        submit = wtforms.SubmitField("Add file(s)")

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

            await _upload_files(project_name, version_name, file_name, file_data)
            return await session.redirect(
                review, success="File(s) added successfully", project_name=project_name, version_name=version_name
            )
        except Exception as e:
            logging.exception("Error adding file(s):")
            await quart.flash(f"Error adding file(s): {e!s}", "error")

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
        await data.release(name=f"{project_name}-{version_name}", _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

        file_path = str(form.file_path.data)
        full_path = str(util.get_release_candidate_draft_dir() / project_name / version_name / file_path)

        # Check that the file exists
        if not await aiofiles.os.path.exists(full_path):
            raise base.ASFQuartException("File does not exist", errorcode=404)

        # Delete the file
        await aiofiles.os.remove(full_path)

    return await session.redirect(
        review, success="File deleted successfully", project_name=project_name, version_name=version_name
    )


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
        release = await data.release(name=f"{project_name}-{version_name}", _project=True).demand(
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

        # Add any relevant tasks to the database
        for task in await tasks.sha_checks(release, str(hash_path)):
            data.add(task)
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


class PromoteForm(util.QuartFormTyped):
    """Form for promoting a candidate draft."""

    candidate_draft_name = wtforms.StringField(
        "Candidate draft name", validators=[wtforms.validators.InputRequired("Candidate draft name is required")]
    )
    confirm_promote = wtforms.BooleanField(
        "Confirmation", validators=[wtforms.validators.DataRequired("You must confirm to proceed with promotion")]
    )
    submit = wtforms.SubmitField("Promote to candidate")


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

        async with db.session() as data:
            try:
                # Get the release
                release = await data.release(name=candidate_draft_name, _project=True).demand(
                    routes.FlashError("Candidate draft not found")
                )

                # Verify that it's in the correct phase
                if release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
                    return await session.redirect(promote, error="This release is not in the candidate draft phase")

                # Promote it to a candidate
                # TODO: Obtain a lock for this
                source = str(util.get_release_candidate_draft_dir() / project_name / version_name)
                target = str(util.get_release_candidate_dir() / project_name / version_name)
                if await aiofiles.os.path.exists(target):
                    return await session.redirect(promote, error="Candidate already exists")
                release.phase = models.ReleasePhase.RELEASE_CANDIDATE_BEFORE_VOTE
                await data.commit()
                await aioshutil.move(source, target)

                return await session.redirect(promote, success="Candidate draft successfully promoted to candidate")

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
        release = await data.release(name=f"{project_name}-{version_name}", _project=True).demand(
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
            release_name=f"{project_name}-{version_name}", path=str(path), status=models.CheckResultStatus.SUCCESS
        ).all()
        path_warnings[path] = await data.check_result(
            release_name=f"{project_name}-{version_name}", path=str(path), status=models.CheckResultStatus.WARNING
        ).all()
        path_errors[path] = await data.check_result(
            release_name=f"{project_name}-{version_name}", path=str(path), status=models.CheckResultStatus.FAILURE
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
        release = await data.release(name=f"{project_name}-{version_name}", _project=True).demand(
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


@routes.committer("/draft/tools/<project_name>/<version_name>/<path:file_path>")
async def tools(session: routes.CommitterSession, project_name: str, version_name: str, file_path: str) -> str:
    """Show the tools for a specific file."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        raise base.ASFQuartException("You do not have access to this project", errorcode=403)

    async with db.session() as data:
        # Check that the release exists
        release = await data.release(name=f"{project_name}-{version_name}", _project=True).demand(
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
    )


@routes.committer("/draft/viewer/<project_name>/<version_name>")
async def viewer(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Show all the files in the rsync upload directory for a release."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        return await session.redirect(add, error="You do not have access to this project")

    # Check that the release exists
    async with db.session() as data:
        release = await data.release(name=f"{project_name}-{version_name}", _project=True).demand(
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
    project_name = str(form.project_name.data)

    # Create the release record in the database
    async with db.session() as data:
        async with data.begin():
            project = await data.project(name=project_name).get()
            if not project:
                raise routes.FlashError("Project not found")

            # Verify user is a committee member or committer of the project
            if project_name not in (p.name for p in await session.user_projects):
                raise routes.FlashError(
                    f"You must be a participant of {project_name} to submit a release candidate",
                )

            release_name = f"{project_name}-{version}"
            # Check that the release does not already exist
            if await data.release(name=release_name).get():
                raise routes.FlashError("Release candidate already exists")

            # Create release record with project
            release = models.Release(
                name=release_name,
                stage=models.ReleaseStage.RELEASE_CANDIDATE,
                phase=models.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
                project_id=project.id,
                project=project,
                version=version,
                created=datetime.datetime.now(datetime.UTC),
            )
            data.add(release)


async def _upload_files(
    project_name: str,
    version_name: str,
    file_name: pathlib.Path | None,
    files: Sequence[datastructures.FileStorage],
) -> None:
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


async def _save_file(file: datastructures.FileStorage, target_path: pathlib.Path) -> None:
    async with aiofiles.open(target_path, "wb") as f:
        while chunk := await asyncio.to_thread(file.stream.read, 8192):
            await f.write(chunk)
