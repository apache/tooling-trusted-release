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
import quart

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.util as util


@routes.committer("/report/<project_name>/<version_name>/<path:rel_path>")
async def release_path(session: routes.CommitterSession, project_name: str, version_name: str, rel_path: str) -> str:
    """Show the report for a specific file."""
    await session.check_access(project_name)
    release = await session.release(project_name, version_name)

    # TODO: When we do more than one thing in a dir, we should use the revision directory directly
    abs_path = util.release_directory(release) / rel_path

    # Check that the file exists
    if not await aiofiles.os.path.exists(abs_path):
        raise base.ASFQuartException("File does not exist", errorcode=404)

    modified = int(await aiofiles.os.path.getmtime(abs_path))
    file_size = await aiofiles.os.path.getsize(abs_path)

    # Get all check results for this file
    async with db.session() as data:
        query = data.check_result(release_name=release.name, primary_rel_path=str(rel_path)).order_by(
            db.validate_instrumented_attribute(models.CheckResult.checker).asc(),
            db.validate_instrumented_attribute(models.CheckResult.created).desc(),
        )
        all_results = await query.all()

    # Filter to get only the most recent result for each checker
    latest_check_results: dict[str, models.CheckResult] = {}
    for result in all_results:
        if result.checker not in latest_check_results:
            latest_check_results[result.checker] = result

    # Convert to a list for the template
    check_results_list = list(latest_check_results.values())

    file_data = {
        "filename": pathlib.Path(rel_path).name,
        "bytes_size": file_size,
        "uploaded": datetime.datetime.fromtimestamp(modified, tz=datetime.UTC),
    }

    return await quart.render_template(
        "report-release-path.html",
        project_name=project_name,
        version_name=version_name,
        rel_path=rel_path,
        package=file_data,
        release=release,
        check_results=check_results_list,
        format_file_size=routes.format_file_size,
    )
