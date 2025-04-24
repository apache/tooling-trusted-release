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

"""preview.py"""

import logging
import pathlib
from typing import Final

import aiofiles.os
import aioshutil
import asfquart
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.revision as revision
import atr.routes as routes
import atr.routes.release as routes_release
import atr.util as util

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")

_LOGGER: Final = logging.getLogger(__name__)


class MoveFileForm(util.QuartFormTyped):
    """Form for moving a file within a preview revision."""

    source_file = wtforms.SelectField("File to move", choices=[], validators=[wtforms.validators.InputRequired()])
    target_directory = wtforms.SelectField(
        "Target directory", choices=[], validators=[wtforms.validators.InputRequired()]
    )
    submit = wtforms.SubmitField("Move file")

    def validate_target_directory(self, field: wtforms.Field) -> None:
        # This validation runs only if both fields have data
        if self.source_file.data and field.data:
            source_path = pathlib.Path(self.source_file.data)
            target_dir = pathlib.Path(field.data)
            if source_path.parent == target_dir:
                raise wtforms.validators.ValidationError("Target directory cannot be the same as the source directory.")


class AnnounceForm(util.QuartFormTyped):
    """Form for announcing a release preview."""

    preview_name = wtforms.StringField(
        "Preview name", validators=[wtforms.validators.InputRequired("Preview name is required")]
    )
    preview_revision = wtforms.StringField(
        "Preview revision", validators=[wtforms.validators.InputRequired("Preview revision is required")]
    )
    confirm_announce = wtforms.BooleanField(
        "Confirmation",
        validators=[wtforms.validators.DataRequired("You must confirm to proceed with announcement")],
    )
    submit = wtforms.SubmitField("Announce release")


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


@routes.committer("/preview/announce", methods=["GET", "POST"])
async def announce(session: routes.CommitterSession) -> str | response.Response:
    """Allow the user to announce a release preview."""

    # Get user's preview releases
    async with db.session() as data:
        releases = await data.release(
            stage=models.ReleaseStage.RELEASE,
            phase=models.ReleasePhase.RELEASE_PREVIEW,
            _committee=True,
            _packages=True,
        ).all()
    user_previews = session.only_user_releases(releases)

    # Create the forms
    announce_form = await AnnounceForm.create_form(
        data=await quart.request.form if (quart.request.method == "POST") else None
    )
    delete_form = await DeleteForm.create_form()

    if (quart.request.method == "POST") and (await announce_form.validate_on_submit()):
        try:
            _preview_name, project_name, version_name, _preview_revision = _announce_form_validate(announce_form)
        except ValueError as e:
            return await session.redirect(announce, error=str(e))

        # Check that the user has access to the project
        async with db.session() as data:
            await session.check_access(project_name)

            try:
                # Get the release
                release = await session.release(
                    project_name, version_name, phase=models.ReleasePhase.RELEASE_PREVIEW, data=data
                )

                if release.revision is None:
                    # Impossible, but to satisfy the type checkers
                    return await session.redirect(announce, error="This release does not have a revision")

                source_base = util.release_directory_base(release)
                source = str(source_base / release.revision)

                # Update the database
                release.phase = models.ReleasePhase.RELEASE
                release.revision = None

                # This must come after updating the release object
                target = str(util.release_directory(release))
                if await aiofiles.os.path.exists(target):
                    return await session.redirect(announce, error="Release already exists")

                await data.commit()

                # Move the revision directory
                await aioshutil.move(source, target)

                # Remove the rest of the preview history
                # This must come after moving the revision directory, otherwise it will be removed too
                await aioshutil.rmtree(str(source_base))

                return await session.redirect(routes_release.releases, success="Preview successfully announced")

            except Exception as e:
                logging.exception("Error announcing preview:")
                return await session.redirect(announce, error=f"Error announcing preview: {e!s}")

    return await quart.render_template(
        "preview-announce.html",
        previews=user_previews,
        announce_form=announce_form,
        delete_form=delete_form,
    )


@routes.committer("/announce/<project_name>/<version_name>")
async def announce_release(
    session: routes.CommitterSession, project_name: str, version_name: str
) -> str | response.Response:
    """Allow the user to announce a release preview."""
    await session.check_access(project_name)

    announce_form = await AnnounceForm.create_form()
    release = await session.release(project_name, version_name, phase=models.ReleasePhase.RELEASE_PREVIEW)
    return await quart.render_template("preview-announce-release.html", release=release, announce_form=announce_form)


@routes.committer("/preview/delete", methods=["POST"])
async def delete(session: routes.CommitterSession) -> response.Response:
    """Delete a preview and all its associated files."""
    form = await DeleteForm.create_form(data=await quart.request.form)

    if not await form.validate_on_submit():
        for _field, errors in form.errors.items():
            for error in errors:
                await quart.flash(f"{error}", "error")
        return await session.redirect(announce)

    preview_name = form.preview_name.data
    if not preview_name:
        return await session.redirect(announce, error="Missing required parameters")

    # Extract project name and version
    try:
        project_name, version = preview_name.rsplit("-", 1)
    except ValueError:
        return await session.redirect(announce, error="Invalid preview name format")

    # Check that the user has access to the project
    async with db.session() as data:
        project = await data.project(name=project_name).get()
        if not project or not any(
            (c.id == project.committee_id and (session.uid in c.committee_members or session.uid in c.committers))
            for c in (await session.user_committees)
        ):
            return await session.redirect(announce, error="You do not have access to this project")

        # Delete the metadata from the database
        async with data.begin():
            try:
                await _delete_preview(data, preview_name)
            except Exception as e:
                logging.exception("Error deleting preview:")
                return await session.redirect(announce, error=f"Error deleting preview: {e!s}")

    # Delete the files on disk, including all revisions
    # We can't use util.release_directory_base here because we don't have the release object
    preview_dir = util.get_release_preview_dir() / project_name / version
    if await aiofiles.os.path.exists(preview_dir):
        await aioshutil.rmtree(preview_dir)

    return await session.redirect(announce, success="Preview deleted successfully")


@routes.committer("/previews")
async def previews(session: routes.CommitterSession) -> str:
    """View all release previews to which the user has access."""
    async with db.session() as data:
        # Get all releases where the user is a PMC member or committer
        releases = await data.release(
            stage=models.ReleaseStage.RELEASE,
            phase=models.ReleasePhase.RELEASE_PREVIEW,
            _committee=True,
            _packages=True,
        ).all()
    user_previews = session.only_user_releases(releases)

    return await quart.render_template(
        "previews.html",
        previews=user_previews,
    )


@routes.committer("/deploy/<project_name>/<version_name>", methods=["GET", "POST"])
async def deploy_release(
    session: routes.CommitterSession, project_name: str, version_name: str
) -> response.Response | str:
    """Deploy a release preview."""
    await session.check_access(project_name)
    release = await session.release(project_name, version_name, phase=models.ReleasePhase.RELEASE_PREVIEW)

    current_revision_dir = util.release_directory(release)
    file_paths_rel: list[pathlib.Path] = []
    unique_dirs: set[pathlib.Path] = {pathlib.Path(".")}

    try:
        for path in await util.paths_recursive(current_revision_dir):
            file_paths_rel.append(path)
            unique_dirs.add(path.parent)
    except FileNotFoundError:
        await quart.flash("Preview revision directory not found.", "error")
        return await session.redirect(previews)

    form = await MoveFileForm.create_form(data=await quart.request.form if (quart.request.method == "POST") else None)

    # Populate choices dynamically for both GET and POST
    form.source_file.choices = sorted([(str(p), str(p)) for p in file_paths_rel])
    form.target_directory.choices = sorted([(str(d), str(d)) for d in unique_dirs])
    can_move = len(unique_dirs) > 1

    if (quart.request.method == "POST") and can_move:
        match r := await _move_file(form, session, project_name, version_name):
            case None:
                pass
            case response.Response():
                return r

    return await quart.render_template(
        "preview-deploy-release.html", release=release, file_paths=sorted(file_paths_rel), form=form, can_move=can_move
    )


@routes.committer("/preview/view/<project_name>/<version_name>")
async def view(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """View all the files in the rsync upload directory for a release."""
    await session.check_access(project_name)

    release = await session.release(project_name, version_name, phase=models.ReleasePhase.RELEASE_PREVIEW)

    # Convert async generator to list
    file_stats = [
        stat
        async for stat in util.content_list(
            util.get_release_preview_dir(), project_name, version_name, release.revision
        )
    ]

    return await quart.render_template(
        "phase-view.html",
        file_stats=file_stats,
        release=release,
        format_datetime=routes.format_datetime,
        format_file_size=routes.format_file_size,
        format_permissions=routes.format_permissions,
        phase="release preview",
        phase_key="preview",
    )


@routes.committer("/preview/view/<project_name>/<version_name>/<path:file_path>")
async def view_path(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response | str:
    """View the content of a specific file in the release preview."""
    await session.check_access(project_name)

    release = await session.release(project_name, version_name, phase=models.ReleasePhase.RELEASE_PREVIEW)
    _max_view_size = 1 * 1024 * 1024
    full_path = util.release_directory(release) / file_path
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
        format_file_size=routes.format_file_size,
        phase_key="preview",
        content_listing=content_listing,
    )


def _announce_form_validate(announce_form: AnnounceForm) -> tuple[str, str, str, str]:
    preview_name = announce_form.preview_name.data
    if not preview_name:
        raise ValueError("Missing required parameters")

    # Extract project name and version
    try:
        project_name, version_name = preview_name.rsplit("-", 1)
    except ValueError:
        raise ValueError("Invalid preview name format")

    preview_revision = announce_form.preview_revision.data
    if not preview_revision:
        raise ValueError("Missing required parameters")

    return preview_name, project_name, version_name, preview_revision


async def _delete_preview(data: db.Session, preview_name: str) -> None:
    """Delete a release preview and all its associated files."""
    # Check that the release exists
    release = await data.release(name=preview_name, _project=True, _packages=True).get()
    if not release:
        raise routes.FlashError("Preview not found")
    if release.phase != models.ReleasePhase.RELEASE_PREVIEW:
        raise routes.FlashError("Release is not in the preview phase")

    # TODO: Abstract this to a function
    # We do something similar in admin.py and draft.py
    # Delete all associated packages first
    for package in release.packages:
        await data.delete(package)

    # Delete any parent links
    await data.ns_text_del_all(release.name + " draft")
    await data.ns_text_del_all(release.name + " preview")

    # Delete the release record
    await data.delete(release)


async def _move_file(
    form: MoveFileForm, session: routes.CommitterSession, project_name: str, version_name: str
) -> response.Response | None:
    if await form.validate_on_submit():
        source_file_rel = pathlib.Path(form.source_file.data)
        target_dir_rel = pathlib.Path(form.target_directory.data)

        try:
            async with revision.create_and_manage(project_name, version_name, session.uid, preview=True) as (
                new_revision_dir,
                new_revision_name,
            ):
                source_path_in_new = new_revision_dir / source_file_rel
                target_path_in_new = new_revision_dir / target_dir_rel / source_file_rel.name

                if await aiofiles.os.path.exists(target_path_in_new):
                    await quart.flash(
                        f"File '{source_file_rel.name}' already exists in '{target_dir_rel}' in new revision.",
                        "error",
                    )
                    return await session.redirect(deploy_release, project_name=project_name, version_name=version_name)

                _LOGGER.info(f"Moving {source_path_in_new} to {target_path_in_new} in new revision {new_revision_name}")
                await aiofiles.os.rename(source_path_in_new, target_path_in_new)

            await quart.flash(
                f"File '{source_file_rel.name}' moved successfully to '{target_dir_rel}' in new revision.", "success"
            )
            return await session.redirect(deploy_release, project_name=project_name, version_name=version_name)

        except FileNotFoundError:
            _LOGGER.exception("File not found during move operation in new revision")
            await quart.flash("Error: Source file not found during move operation.", "error")
        except OSError as e:
            _LOGGER.exception("Error moving file in new revision")
            await quart.flash(f"Error moving file: {e}", "error")
        except Exception as e:
            _LOGGER.exception("Unexpected error during file move")
            await quart.flash(f"An unexpected error occurred: {e!s}", "error")
            return await session.redirect(deploy_release, project_name=project_name, version_name=version_name)
    else:
        for field, errors in form.errors.items():
            field_label = getattr(getattr(form, field, None), "label", None)
            label_text = field_label.text if field_label else field.replace("_", " ").title()
            for error in errors:
                await quart.flash(f"{label_text}: {error}", "warning")
