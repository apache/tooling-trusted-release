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

"""candidate.py"""

import logging

import asfquart
import asfquart.base as base
import werkzeug.wrappers.response as response

import atr.db as db
import atr.models.sql as sql
import atr.routes as routes
import atr.routes.root as root
import atr.template as template
import atr.util as util

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")


@routes.committer("/candidate/delete", methods=["POST"])
async def delete(session: routes.CommitterSession) -> response.Response:
    """Delete a release candidate."""
    return await session.redirect(root.index, error="Not yet implemented")


@routes.committer("/candidate/view/<project_name>/<version_name>")
async def view(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """View all the files in the rsync upload directory for a release."""
    await session.check_access(project_name)

    # Check that the release exists
    async with db.session() as data:
        release = await data.release(name=sql.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

    # Convert async generator to list
    file_stats = [
        stat
        async for stat in util.content_list(
            util.get_unfinished_dir(), project_name, version_name, release.unwrap_revision_number
        )
    ]
    # Sort the files by FileStat.path
    file_stats.sort(key=lambda fs: fs.path)
    logging.debug(f"File stats: {file_stats}")

    return await template.render(
        # TODO: Move to somewhere appropriate
        "phase-view.html",
        file_stats=file_stats,
        release=release,
        format_datetime=util.format_datetime,
        format_file_size=util.format_file_size,
        format_permissions=util.format_permissions,
        phase="release candidate",
        phase_key="candidate",
    )


@routes.committer("/candidate/view/<project_name>/<version_name>/<path:file_path>")
async def view_path(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response | str:
    """View the content of a specific file in the release candidate."""
    await session.check_access(project_name)

    release = await session.release(project_name, version_name, phase=sql.ReleasePhase.RELEASE_CANDIDATE)
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
        phase_key="candidate",
        content_listing=content_listing,
    )
