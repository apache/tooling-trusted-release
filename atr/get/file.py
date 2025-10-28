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

import werkzeug.wrappers.response as response

import atr.blueprints.get as get
import atr.template as template
import atr.util as util
import atr.web as web


@get.committer("/file/<project_name>/<version_name>/<path:file_path>")
async def selected_path(
    session: web.Committer, project_name: str, version_name: str, file_path: str
) -> response.Response | str:
    """View the content of a specific file in the release candidate draft."""
    # TODO: Make this independent of the release phase
    await session.check_access(project_name)

    release = await session.release(project_name, version_name)

    # Limit to 256 KiB
    _max_view_size = 256 * 1024
    full_path = util.release_directory(release) / file_path

    # Attempt to get an archive listing
    # This will be None if the file is not an archive
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
        content_listing=content_listing,
        format_file_size=util.format_file_size,
        phase_key="draft",
        max_view_size=util.format_file_size(_max_view_size),
    )
