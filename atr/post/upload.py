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

import atr.blueprints.post as post
import atr.get as get
import atr.log as log
import atr.shared as shared
import atr.storage as storage
import atr.web as web


@post.committer("/upload/<project_name>/<version_name>")
@post.form(shared.upload.UploadForm)
async def selected(
    session: web.Committer, upload_form: shared.upload.UploadForm, project_name: str, version_name: str
) -> web.WerkzeugResponse:
    await session.check_access(project_name)

    match upload_form:
        case shared.upload.AddFilesForm() as add_form:
            return await _add_files(session, add_form, project_name, version_name)

        case shared.upload.SvnImportForm() as svn_form:
            return await _svn_import(session, svn_form, project_name, version_name)


async def _add_files(
    session: web.Committer, add_form: shared.upload.AddFilesForm, project_name: str, version_name: str
) -> web.WerkzeugResponse:
    try:
        file_name = add_form.file_name
        file_data = add_form.file_data

        async with storage.write(session) as write:
            wacp = await write.as_project_committee_participant(project_name)
            number_of_files = await wacp.release.upload_files(project_name, version_name, file_name, file_data)

        plural = number_of_files != 1
        return await session.redirect(
            get.compose.selected,
            success=f"{number_of_files} file{'s' if plural else ''} added successfully",
            project_name=project_name,
            version_name=version_name,
        )
    except Exception as e:
        log.exception("Error adding file:")
        await quart.flash(f"Error adding file: {e!s}", "error")
        return await session.redirect(
            get.upload.selected,
            project_name=project_name,
            version_name=version_name,
        )


async def _svn_import(
    session: web.Committer, svn_form: shared.upload.SvnImportForm, project_name: str, version_name: str
) -> web.WerkzeugResponse:
    try:
        target_subdirectory = str(svn_form.target_subdirectory) if svn_form.target_subdirectory else None
        async with storage.write(session) as write:
            wacp = await write.as_project_committee_participant(project_name)
            await wacp.release.import_from_svn(
                project_name,
                version_name,
                str(svn_form.svn_url),
                svn_form.revision,
                target_subdirectory,
            )

        return await session.redirect(
            get.compose.selected,
            success="SVN import task queued successfully",
            project_name=project_name,
            version_name=version_name,
        )
    except Exception:
        log.exception("Error queueing SVN import task:")
        return await session.redirect(
            get.upload.selected,
            error="Error queueing SVN import task",
            project_name=project_name,
            version_name=version_name,
        )
