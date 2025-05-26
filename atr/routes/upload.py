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

import asyncio
import logging
import pathlib
from collections.abc import Sequence

import aiofiles
import quart
import werkzeug.datastructures as datastructures
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.revision as revision
import atr.routes as routes
import atr.routes.compose as compose
import atr.template as template
import atr.util as util


class SvnImportForm(util.QuartFormTyped):
    """Form for importing files from SVN into a draft."""

    svn_url = wtforms.URLField(
        "SVN URL",
        validators=[
            wtforms.validators.InputRequired("SVN URL is required."),
            wtforms.validators.URL(require_tld=False),
        ],
        description="The URL to the public SVN directory.",
    )
    revision = wtforms.StringField(
        "Revision",
        default="HEAD",
        validators=[],
        description="Specify an SVN revision number or leave as HEAD for the latest.",
    )
    target_subdirectory = wtforms.StringField(
        "Target subdirectory",
        validators=[],
        description="Optional: Subdirectory to place imported files, defaulting to the root.",
    )
    submit = wtforms.SubmitField("Queue SVN import task")


@routes.committer("/upload/<project_name>/<version_name>", methods=["GET", "POST"])
async def selected(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Show a page to allow the user to add files to a candidate draft."""
    await session.check_access(project_name)

    class AddFilesForm(util.QuartFormTyped):
        """Form for adding files to a release candidate."""

        file_name = wtforms.StringField(
            "File name",
            description="Optional: Enter a file name to use when saving the"
            " file in the release candidate. Only available when uploading a single file.",
        )
        file_data = wtforms.MultipleFileField(
            "Files",
            validators=[wtforms.validators.InputRequired("At least one file is required")],
            description="Select the files to upload.",
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
                compose.selected,
                success=f"{number_of_files} file{'' if number_of_files == 1 else 's'} added successfully",
                project_name=project_name,
                version_name=version_name,
            )
        except Exception as e:
            logging.exception("Error adding file:")
            await quart.flash(f"Error adding file: {e!s}", "error")

    svn_form = await SvnImportForm.create_form()

    async with db.session() as data:
        release = await session.release(project_name, version_name, data=data)
        user_ssh_keys = await data.ssh_key(asf_uid=session.uid).all()

    return await template.render(
        "upload-selected.html",
        asf_id=session.uid,
        server_domain=session.app_host,
        release=release,
        project_name=project_name,
        version_name=version_name,
        form=form,
        svn_form=svn_form,
        user_ssh_keys=user_ssh_keys,
    )


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
    number_of_files = len(files)
    description = f"Upload of {number_of_files} file{'' if number_of_files == 1 else 's'} through web interface"
    async with revision.create_and_manage(project_name, version_name, asf_uid, description=description) as creating:

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
            target_path = creating.interim_path / relative_file_path
            return target_path

        # Save each uploaded file to the new revision directory
        for file in files:
            target_path = get_target_path(file)
            # Ensure parent directories exist within the new revision
            target_path.parent.mkdir(parents=True, exist_ok=True)
            await _save_file(file, target_path)

    return len(files)
