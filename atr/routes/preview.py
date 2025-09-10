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

import asfquart
import quart
import werkzeug.wrappers.response as response

import atr.construct as construct
import atr.forms as forms
import atr.log as log
import atr.models.sql as sql
import atr.routes as routes
import atr.routes.root as root
import atr.storage as storage
import atr.template as template
import atr.util as util

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")


class AnnouncePreviewForm(forms.Typed):
    """Form for validating preview request data."""

    subject = forms.optional("Subject")
    body = forms.textarea("Body")


class DeleteForm(forms.Typed):
    """Form for deleting a release preview."""

    release_name = forms.hidden()
    project_name = forms.hidden()
    version_name = forms.hidden()
    confirm_delete = forms.string("Confirmation", validators=forms.constant("DELETE"))
    submit = forms.submit("Delete preview")


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
        log.exception("Error generating announcement preview:")
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
    async with storage.write(session.uid) as write:
        wacp = await write.as_project_committee_member(project_name)
        await wacp.release.delete(
            project_name, version_name, phase=sql.ReleasePhase.RELEASE_PREVIEW, include_downloads=False
        )

    return await session.redirect(root.index, success="Preview deleted successfully")


@routes.committer("/preview/view/<project_name>/<version_name>")
async def view(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """View all the files in the rsync upload directory for a release."""
    await session.check_access(project_name)

    release = await session.release(project_name, version_name, phase=sql.ReleasePhase.RELEASE_PREVIEW)

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

    release = await session.release(project_name, version_name, phase=sql.ReleasePhase.RELEASE_PREVIEW)
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
