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
import contextlib
import datetime
import logging
import pathlib
from collections.abc import Callable

import aiofiles.os
import asfquart.base as base
import quart
import sqlmodel
import werkzeug.wrappers.response as response

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.util as util


@routes.committer("/revisions/<project_name>/<version_name>")
async def selected(session: routes.CommitterSession, project_name: str, version_name: str) -> str:
    """Show the revision history for a release candidate draft or release preview."""
    await session.check_access(project_name)

    try:
        release = await session.release(project_name, version_name)
        phase_key = "draft"
    except base.ASFQuartException:
        release = await session.release(project_name, version_name, phase=models.ReleasePhase.RELEASE_PREVIEW)
        phase_key = "preview"
    release_dir = util.release_directory_base(release)

    revision_dirs: list[str] = []
    with contextlib.suppress(FileNotFoundError):
        for entry in await aiofiles.os.listdir(str(release_dir)):
            # Match pattern like "user@YYYY-MM-DDTHH.MM.SS.fffZ"
            if "@" in entry and entry.endswith("Z"):
                if await aiofiles.os.path.isdir(release_dir / entry):
                    revision_dirs.append(entry)

    # Sort revisions by timestamp
    def sort_key(rev_name: str) -> datetime.datetime:
        try:
            # Remove trailing Z, though we could just put it in the template pattern
            timestamp_str = rev_name.split("@", 1)[1][:-1]
            return datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H.%M.%S.%f")
        except (IndexError, ValueError):
            # Should not happen for valid names, put invalid ones last
            return datetime.datetime.min

    # Sort revisions by timestamp, newest first
    revision_dirs.sort(key=sort_key, reverse=True)

    async with db.session() as data:
        # Get parent links using a direct query due to the use of in_(...)
        query = sqlmodel.select(models.TextValue).where(
            models.TextValue.ns == release.name + f" {phase_key}",
            db.validate_instrumented_attribute(models.TextValue.key).in_(revision_dirs),
        )
        parent_links_result = await data.execute(query)
        parent_map = {link.key: link.value for link in parent_links_result.scalars().all()}

    # Determine the current revision
    current_revision_name = release.revision

    revision_history = []
    prev_revision_files: set[pathlib.Path] | None = None
    prev_revision_name: str | None = None

    # Oldest to newest, to build diffs relative to previous revision
    for rev_name in reversed(revision_dirs):
        revision_data, current_revision_files = await _revisions_process(
            rev_name,
            release_dir,
            parent_map,
            prev_revision_files,
            prev_revision_name,
            sort_key,
        )
        revision_history.append(revision_data)
        prev_revision_files = current_revision_files
        prev_revision_name = rev_name

    return await quart.render_template(
        "revisions-selected.html",
        project_name=project_name,
        version_name=version_name,
        release=release,
        phase_key=phase_key,
        revision_history=list(reversed(revision_history)),
        current_revision_name=current_revision_name,
    )


@routes.committer("/revisions/<project_name>/<version_name>", methods=["POST"])
async def selected_post(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response:
    """Set a specific revision as the latest for a candidate draft or release preview."""
    await session.check_access(project_name)
    form_data = await quart.request.form
    revision_name = form_data.get("revision_name")
    if not revision_name:
        raise base.ASFQuartException("Missing revision name", errorcode=400)

    try:
        # Target must be relative for the symlink
        # TODO: We should probably log who is doing this, to create an audit trail
        async with db.session() as data:
            try:
                release = await session.release(project_name, version_name, data=data)
            except base.ASFQuartException:
                release = await session.release(
                    project_name, version_name, phase=models.ReleasePhase.RELEASE_PREVIEW, data=data
                )
            release_dir = util.release_directory_base(release)

            # Check that the target revision directory exists
            target_revision_dir = release_dir / revision_name
            if not await aiofiles.os.path.isdir(target_revision_dir):
                raise base.ASFQuartException("Target revision directory not found", errorcode=404)

            release.revision = revision_name
            await data.commit()
    except base.ASFQuartException as e:
        raise e
    except Exception as e:
        logging.exception("Error setting revision:")
        return await session.redirect(
            selected,
            error=f"Failed to set revision {revision_name} as latest: {e!s}",
            project_name=project_name,
            version_name=version_name,
        )

    return await session.redirect(
        selected,
        success=f"Revision {revision_name} set as latest",
        project_name=project_name,
        version_name=version_name,
    )


async def _revisions_process(
    rev_name: str,
    release_dir: pathlib.Path,
    parent_map: dict[str, str],
    prev_revision_files: set[pathlib.Path] | None,
    prev_revision_name: str | None,
    sort_key: Callable[[str], datetime.datetime],
) -> tuple[dict, set[pathlib.Path]]:
    """Process a single revision and calculate its diff from the previous."""
    current_revision_dir = release_dir / rev_name
    current_revision_files = set(await util.paths_recursive(current_revision_dir))
    parent_name = parent_map.get(rev_name)

    added_files: set[pathlib.Path] = set()
    removed_files: set[pathlib.Path] = set()
    modified_files: set[pathlib.Path] = set()

    if (prev_revision_files is not None) and (prev_revision_name is not None):
        added_files = current_revision_files - prev_revision_files
        removed_files = prev_revision_files - current_revision_files
        common_files = current_revision_files & prev_revision_files

        # Check modification times for common files
        parent_revision_dir = release_dir / prev_revision_name
        mtime_tasks = []
        for common_file in common_files:

            async def check_mtime(file_path: pathlib.Path) -> tuple[pathlib.Path, bool]:
                try:
                    parent_mtime = await aiofiles.os.path.getmtime(parent_revision_dir / file_path)
                    current_mtime = await aiofiles.os.path.getmtime(current_revision_dir / file_path)
                    return file_path, parent_mtime != current_mtime
                except OSError:
                    # Treat errors as modified
                    return file_path, True

            mtime_tasks.append(check_mtime(common_file))

        results = await asyncio.gather(*mtime_tasks)
        modified_files = {f for f, modified in results if modified}
    else:
        # First revision, all files are considered added
        added_files = current_revision_files

    try:
        editor = rev_name.split("@", 1)[0]
        timestamp = sort_key(rev_name)
    except (ValueError, IndexError):
        editor = "Unknown"
        timestamp = None

    revision_data = {
        "name": rev_name,
        "editor": editor,
        "timestamp": timestamp,
        "parent": parent_name,
        "added": sorted(list(added_files)),
        "removed": sorted(list(removed_files)),
        "modified": sorted(list(modified_files)),
    }
    return revision_data, current_revision_files
