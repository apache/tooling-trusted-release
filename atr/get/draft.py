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


from __future__ import annotations

import datetime
import pathlib
from typing import TYPE_CHECKING

import aiofiles.os
import asfquart.base as base

import atr.blueprints.get as get
import atr.forms as forms
import atr.template as template
import atr.util as util
import atr.web as web

if TYPE_CHECKING:
    import werkzeug.wrappers.response as response


@get.committer("/draft/tools/<project_name>/<version_name>/<path:file_path>")
async def tools(session: web.Committer, project_name: str, version_name: str, file_path: str) -> str:
    """Show the tools for a specific file."""
    await session.check_access(project_name)

    release = await session.release(project_name, version_name)
    full_path = str(util.release_directory(release) / file_path)

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

    return await template.render(
        "draft-tools.html",
        asf_id=session.uid,
        project_name=project_name,
        version_name=version_name,
        file_path=file_path,
        file_data=file_data,
        release=release,
        format_file_size=util.format_file_size,
        empty_form=await forms.Empty.create_form(),
    )


# TODO: Should we deprecate this and ensure compose covers it all?
# If we did that, we'd lose the exhaustive use of the abstraction
@get.committer("/draft/view/<project_name>/<version_name>")
async def view(session: web.Committer, project_name: str, version_name: str) -> response.Response | str:
    """View all the files in the rsync upload directory for a release."""
    await session.check_access(project_name)

    release = await session.release(project_name, version_name)

    # Convert async generator to list
    revision_number = release.latest_revision_number
    file_stats = []
    if revision_number is not None:
        file_stats = [
            stat
            async for stat in util.content_list(util.get_unfinished_dir(), project_name, version_name, revision_number)
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
        phase="release candidate draft",
        phase_key="draft",
    )
