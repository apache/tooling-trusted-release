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

import pathlib

import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.forms as forms
import atr.get.compose as compose
import atr.log as log
import atr.storage as storage
import atr.template as template
import atr.web as web


class AddFilesForm(forms.Typed):
    """Form for adding files to a release candidate."""

    file_name = forms.optional(
        "File name",
        description="Optional: Enter a file name to use when saving the "
        "file in the release candidate. Only available when uploading a "
        "single file.",
    )
    file_data = forms.files("Files", description="Select the files to upload.")
    submit = forms.submit("Add files")

    def validate_file_name(self, field: wtforms.Field) -> bool:
        if field.data and len(self.file_data.data) > 1:
            raise wtforms.validators.ValidationError("File name can only be used when uploading a single file")
        return True


class SvnImportForm(forms.Typed):
    """Form for importing files from SVN into a draft."""

    svn_url = forms.url("SVN URL", description="The URL to the public SVN directory.")
    revision = forms.string(
        "Revision", default="HEAD", description="Specify an SVN revision number or leave as HEAD for the latest."
    )
    target_subdirectory = forms.string(
        "Target subdirectory", description="Optional: Subdirectory to place imported files, defaulting to the root."
    )
    submit = forms.submit("Queue SVN import task")


async def selected(session: web.Committer, project_name: str, version_name: str) -> response.Response | str:
    """Show a page to allow the user to add files to a candidate draft."""
    await session.check_access(project_name)

    form = await AddFilesForm.create_form()
    if await form.validate_on_submit():
        try:
            file_name = None
            if isinstance(form.file_name.data, str) and form.file_name.data:
                file_name = pathlib.Path(form.file_name.data)
            file_data = form.file_data.data

            async with storage.write(session) as write:
                wacp = await write.as_project_committee_participant(project_name)
                number_of_files = await wacp.release.upload_files(project_name, version_name, file_name, file_data)
            return await session.redirect(
                compose.selected,
                success=f"{number_of_files} file{'' if number_of_files == 1 else 's'} added successfully",
                project_name=project_name,
                version_name=version_name,
            )
        except Exception as e:
            log.exception("Error adding file:")
            await quart.flash(f"Error adding file: {e!s}", "error")

    svn_form = await SvnImportForm.create_form()

    async with db.session() as data:
        release = await session.release(project_name, version_name, data=data)
        user_ssh_keys = await data.ssh_key(asf_uid=session.uid).all()

    return await template.render(
        "upload-selected.html",
        asf_id=session.uid,
        server_domain=session.app_host.split(":", 1)[0],
        server_host=session.app_host,
        release=release,
        project_name=project_name,
        version_name=version_name,
        form=form,
        svn_form=svn_form,
        user_ssh_keys=user_ssh_keys,
    )
