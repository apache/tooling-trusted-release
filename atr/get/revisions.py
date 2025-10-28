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
import pathlib

import aiofiles.os
import asfquart.base as base
import sqlalchemy.orm as orm
import sqlmodel

import atr.blueprints.get as get
import atr.db as db
import atr.forms as forms
import atr.models.schema as schema
import atr.models.sql as sql
import atr.template as template
import atr.util as util
import atr.web as web


@get.committer("/revisions/<project_name>/<version_name>")
async def selected(session: web.Committer, project_name: str, version_name: str) -> str:
    """Show the revision history for a release candidate draft or release preview."""
    await session.check_access(project_name)

    try:
        release = await session.release(project_name, version_name)
        phase_key = "draft"
    except base.ASFQuartException:
        release = await session.release(project_name, version_name, phase=sql.ReleasePhase.RELEASE_PREVIEW)
        phase_key = "preview"
    release_dir = util.release_directory_base(release)

    # Determine the current revision
    latest_revision_number = release.latest_revision_number
    if latest_revision_number is None:
        # TODO: Set an error message, and redirect to the release page?
        ...

    # Oldest to newest, to build diffs relative to previous revision
    async with db.session() as data_for_revisions:
        revisions_stmt = (
            sqlmodel.select(sql.Revision)
            .where(sql.Revision.release_name == release.name)
            .order_by(sql.validate_instrumented_attribute(sql.Revision.seq))
            .options(orm.selectinload(sql.validate_instrumented_attribute(sql.Revision.parent)))
        )
        revisions_result = await data_for_revisions.execute(revisions_stmt)
        revisions_list: list[sql.Revision] = list(revisions_result.scalars().all())

    revision_history = []
    loop_prev_revision_files: set[pathlib.Path] | None = None
    loop_prev_revision_number: str | None = None
    for current_db_revision in revisions_list:
        current_files_for_diff, files_diff_for_current = await _revision_files_diff(
            revision_number=current_db_revision.number,
            release_dir=release_dir,
            prev_revision_files=loop_prev_revision_files,
            prev_revision_number=loop_prev_revision_number,
        )
        revision_history.append((current_db_revision, files_diff_for_current))
        loop_prev_revision_files = current_files_for_diff
        loop_prev_revision_number = current_db_revision.number

    return await template.render(
        "revisions-selected.html",
        project_name=project_name,
        version_name=version_name,
        release=release,
        phase_key=phase_key,
        revision_history=list(reversed(revision_history)),
        latest_revision_number=latest_revision_number,
        empty_form=await forms.Empty.create_form(),
    )


class FilesDiff(schema.Strict):
    added: list[pathlib.Path]
    removed: list[pathlib.Path]
    modified: list[pathlib.Path]


async def _revision_files_diff(
    revision_number: str,
    release_dir: pathlib.Path,
    prev_revision_files: set[pathlib.Path] | None,
    prev_revision_number: str | None,
) -> tuple[set[pathlib.Path], FilesDiff]:
    """Process a single revision and calculate its diff from the previous."""
    latest_revision_dir = release_dir / revision_number
    latest_revision_files = {path async for path in util.paths_recursive(latest_revision_dir)}

    added_files: set[pathlib.Path] = set()
    removed_files: set[pathlib.Path] = set()
    modified_files: set[pathlib.Path] = set()

    if (prev_revision_files is not None) and (prev_revision_number is not None):
        added_files = latest_revision_files - prev_revision_files
        removed_files = prev_revision_files - latest_revision_files
        common_files = latest_revision_files & prev_revision_files

        # Check modification times for common files
        parent_revision_dir = release_dir / prev_revision_number
        mtime_tasks = []
        for common_file in common_files:

            async def check_mtime(file_path: pathlib.Path) -> tuple[pathlib.Path, bool]:
                try:
                    parent_mtime = await aiofiles.os.path.getmtime(parent_revision_dir / file_path)
                    latest_mtime = await aiofiles.os.path.getmtime(latest_revision_dir / file_path)
                    return file_path, parent_mtime != latest_mtime
                except OSError:
                    # Treat errors as modified
                    return file_path, True

            mtime_tasks.append(check_mtime(common_file))

        results = await asyncio.gather(*mtime_tasks)
        modified_files = {f for f, modified in results if modified}
    else:
        # First revision, all files are considered added
        added_files = latest_revision_files

    files_diff = FilesDiff(
        added=sorted(list(added_files)),
        removed=sorted(list(removed_files)),
        modified=sorted(list(modified_files)),
    )
    return latest_revision_files, files_diff
