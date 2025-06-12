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

import atr.construct as construct
import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.routes.root as root
import atr.template as template
import atr.util as util

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")


class AnnouncePreviewForm(util.QuartFormTyped):
    """Form for validating preview request data."""

    subject = wtforms.StringField("Subject", validators=[wtforms.validators.Optional()])
    body = wtforms.TextAreaField("Body", validators=[wtforms.validators.InputRequired("Body is required for preview")])


class DeleteForm(util.QuartFormTyped):
    """Form for deleting a release preview."""

    release_name = wtforms.HiddenField(validators=[wtforms.validators.InputRequired()])
    project_name = wtforms.HiddenField(validators=[wtforms.validators.InputRequired()])
    version_name = wtforms.HiddenField(validators=[wtforms.validators.InputRequired()])
    confirm_delete = wtforms.StringField(
        "Confirmation",
        validators=[
            wtforms.validators.InputRequired("Confirmation is required"),
            wtforms.validators.Regexp("^DELETE$", message="Please type DELETE to confirm"),
        ],
    )
    submit = wtforms.SubmitField("Delete preview")


@routes.committer("/preview/announce/<project_name>/<version_name>", methods=["POST"])
async def announce_preview(
    session: routes.CommitterSession, project_name: str, version_name: str
) -> quart.wrappers.response.Response | str:
    """Generate a preview of the announcement email body."""

    form = await AnnouncePreviewForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        error_message = "Invalid preview request"
        if form.errors:
            error_details = "; ".join([f"{field}: {', '.join(errs)}" for field, errs in form.errors.items()])
            error_message = f"{error_message}: {error_details}"
        return quart.Response(f"Error: {error_message}", status=400, mimetype="text/plain")

    try:
        # Construct options and generate body
        options = construct.AnnounceReleaseOptions(
            asfuid=session.uid,
            fullname=session.fullname,
            project_name=project_name,
            version_name=version_name,
        )
        preview_body = await construct.announce_release_body(str(form.body.data), options)

        return quart.Response(preview_body, mimetype="text/plain")

    except Exception as e:
        logging.exception("Error generating announcement preview:")
        return quart.Response(f"Error generating preview: {e!s}", status=500, mimetype="text/plain")


@routes.committer("/preview/delete", methods=["POST"])
async def delete(session: routes.CommitterSession) -> response.Response:
    """Delete a preview and all its associated files."""
    form = await DeleteForm.create_form(data=await quart.request.form)

    if not await form.validate_on_submit():
        for _field, errors in form.errors.items():
            for error in errors:
                await quart.flash(f"{error}", "error")
        return await session.redirect(root.index)

    release_name = form.release_name.data
    project_name = form.project_name.data
    version_name = form.version_name.data
    if not (release_name and project_name and version_name):
        return await session.redirect(root.index, error="Missing required parameters")

    # Check that the user has access to the project
    async with db.session() as data:
        project = await data.project(name=project_name, status=models.ProjectStatus.ACTIVE).get()
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
                await _delete_preview(data, release_name)
            except Exception as e:
                logging.exception("Error deleting preview:")
                return await session.redirect(root.index, error=f"Error deleting preview: {e!s}")

    # Delete the files on disk, including all revisions
    # We can't use util.release_directory_base here because we don't have the release object
    preview_dir = util.get_unfinished_dir() / project_name / version_name
    if await aiofiles.os.path.exists(preview_dir):
        await aioshutil.rmtree(preview_dir)

    return await session.redirect(root.index, success="Preview deleted successfully")


@routes.committer("/preview/view/<project_name>/<version_name>")
async def view(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """View all the files in the rsync upload directory for a release."""
    await session.check_access(project_name)

    release = await session.release(project_name, version_name, phase=models.ReleasePhase.RELEASE_PREVIEW)

    # Convert async generator to list
    # There must be a revision on a preview
    file_stats = [
        stat
        async for stat in util.content_list(
            util.get_unfinished_dir(), project_name, version_name, release.unwrap_revision_number
        )
    ]
    # Sort the files by FileStat.path
    file_stats.sort(key=lambda fs: fs.path)

    return await template.render(
        # TODO: Move to somewhere appropriate
        "phase-view.html",
        file_stats=file_stats,
        release=release,
        format_datetime=util.format_datetime,
        format_file_size=util.format_file_size,
        format_permissions=util.format_permissions,
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
    return await template.render(
        "file-selected-path.html",
        release=release,
        project_name=project_name,
        version_name=version_name,
        file_path=file_path,
        content=content,
        is_text=is_text,
        is_truncated=is_truncated,
        error_message=error_message,
        format_file_size=util.format_file_size,
        phase_key="preview",
        content_listing=content_listing,
    )


async def _delete_preview(data: db.Session, release_name: str) -> None:
    """Delete a release preview and all its associated files."""
    # Check that the release exists
    release = await data.release(name=release_name, _project=True).get()
    if not release:
        raise routes.FlashError("Preview not found")
    if release.phase != models.ReleasePhase.RELEASE_PREVIEW:
        raise routes.FlashError("Release is not in the preview phase")

    # Delete the release record
    await data.delete(release)
