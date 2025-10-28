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

import quart
import werkzeug.wrappers.response as response

import atr.blueprints.post as post
import atr.construct as construct
import atr.forms as forms
import atr.log as log
import atr.models.sql as sql
import atr.storage as storage
import atr.web as web


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


@post.committer("/preview/announce/<project_name>/<version_name>")
async def announce_preview(
    session: web.Committer, project_name: str, version_name: str
) -> quart.wrappers.response.Response | str:
    """Generate a preview of the announcement email body."""

    # TODO: Where does this come from? A static template?
    form = await AnnouncePreviewForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        error_message = "Invalid preview request"
        if form.errors:
            error_details = "; ".join([f"{field}: {', '.join(errs)}" for field, errs in form.errors.items()])
            error_message = f"{error_message}: {error_details}"
        return web.TextResponse(f"Error: {error_message}", status=400)

    try:
        # Construct options and generate body
        options = construct.AnnounceReleaseOptions(
            asfuid=session.uid,
            fullname=session.fullname,
            project_name=project_name,
            version_name=version_name,
        )
        preview_body = await construct.announce_release_body(str(form.body.data), options)

        return web.TextResponse(preview_body)

    except Exception as e:
        log.exception("Error generating announcement preview:")
        return web.TextResponse(f"Error generating preview: {e!s}", status=500)


@post.committer("/preview/delete")
async def delete(session: web.Committer) -> response.Response:
    """Delete a preview and all its associated files."""
    import atr.get.root as root

    # TODO: Where does this come from? A static template?
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
    async with storage.write(session) as write:
        wacp = await write.as_project_committee_participant(project_name)
        await wacp.release.delete(
            project_name, version_name, phase=sql.ReleasePhase.RELEASE_PREVIEW, include_downloads=False
        )

    return await session.redirect(root.index, success="Preview deleted successfully")
