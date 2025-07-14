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

import datetime
import pathlib

import aiofiles.os
import asfquart.base as base

import atr.db as db
import atr.models.sql as sql
import atr.routes as routes
import atr.template as template
import atr.util as util


@routes.committer("/report/<project_name>/<version_name>/<path:rel_path>")
async def selected_path(session: routes.CommitterSession, project_name: str, version_name: str, rel_path: str) -> str:
    """Show the report for a specific file."""
    await session.check_access(project_name)

    # If the draft is not found, we try to get the release candidate
    try:
        release = await session.release(project_name, version_name)
    except base.ASFQuartException:
        release = await session.release(project_name, version_name, phase=sql.ReleasePhase.RELEASE_CANDIDATE)

    # TODO: When we do more than one thing in a dir, we should use the revision directory directly
    abs_path = util.release_directory(release) / rel_path
    if release.latest_revision_number is None:
        raise base.ASFQuartException("Release has no revision", errorcode=500)

    # Check that the file exists
    if not await aiofiles.os.path.exists(abs_path):
        raise base.ASFQuartException("File does not exist", errorcode=404)

    modified = int(await aiofiles.os.path.getmtime(abs_path))
    file_size = await aiofiles.os.path.getsize(abs_path)

    # Get all check results for this file
    async with db.session() as data:
        query = data.check_result(
            release_name=release.name,
            revision_number=release.latest_revision_number,
            primary_rel_path=str(rel_path),
        ).order_by(
            sql.validate_instrumented_attribute(sql.CheckResult.checker).asc(),
            sql.validate_instrumented_attribute(sql.CheckResult.created).desc(),
        )
        all_results = await query.all()

    # Filter to separate the primary and member results
    primary_results_list = []
    member_results_list: dict[str, list[sql.CheckResult]] = {}
    for result in all_results:
        if result.member_rel_path is None:
            primary_results_list.append(result)
        else:
            member_results_list.setdefault(result.member_rel_path, []).append(result)

    # Order primary results by checker name
    primary_results_list.sort(key=lambda r: r.checker)

    # Order member results by relative path and then by checker name
    for member_rel_path in sorted(member_results_list.keys()):
        member_results_list[member_rel_path].sort(key=lambda r: r.checker)

    file_data = {
        "filename": pathlib.Path(rel_path).name,
        "bytes_size": file_size,
        "uploaded": datetime.datetime.fromtimestamp(modified, tz=datetime.UTC),
    }

    return await template.render(
        "report-selected-path.html",
        project_name=project_name,
        version_name=version_name,
        rel_path=rel_path,
        package=file_data,
        release=release,
        primary_results=primary_results_list,
        member_results=member_results_list,
        format_file_size=util.format_file_size,
        empty_form=await util.EmptyForm.create_form(),
    )
