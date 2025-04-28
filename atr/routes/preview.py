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

import aiofiles.os
import aioshutil
import asfquart
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.routes.root as root
import atr.util as util

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")


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


@routes.committer("/preview/delete", methods=["POST"])
async def delete(session: routes.CommitterSession) -> response.Response:
    """Delete a preview and all its associated files."""
    form = await DeleteForm.create_form(data=await quart.request.form)

    if not await form.validate_on_submit():
        for _field, errors in form.errors.items():
            for error in errors:
                await quart.flash(f"{error}", "error")
        return await session.redirect(root.index)

    preview_name = form.preview_name.data
    if not preview_name:
        return await session.redirect(root.index, error="Missing required parameters")

    # Extract project name and version
    try:
        project_name, version = preview_name.rsplit("-", 1)
    except ValueError:
        return await session.redirect(root.index, error="Invalid preview name format")

    # Check that the user has access to the project
    async with db.session() as data:
        project = await data.project(name=project_name).get()
        if not project or not any(
            (
                (c.name == project.committee_name)
                and ((session.uid in c.committee_members) or (session.uid in c.committers))
            )
            for c in (await session.user_committees)
        ):
            return await session.redirect(root.index, error="You do not have access to this project")

        # Delete the metadata from the database
        async with data.begin():
            try:
                await _delete_preview(data, preview_name)
            except Exception as e:
                logging.exception("Error deleting preview:")
                return await session.redirect(root.index, error=f"Error deleting preview: {e!s}")

    # Delete the files on disk, including all revisions
    # We can't use util.release_directory_base here because we don't have the release object
    preview_dir = util.get_release_preview_dir() / project_name / version
    if await aiofiles.os.path.exists(preview_dir):
        await aioshutil.rmtree(preview_dir)

    return await session.redirect(root.index, success="Preview deleted successfully")


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
        # TODO: Move to somewhere appropriate
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
        "file-selected-path.html",
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
