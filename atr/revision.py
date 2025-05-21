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
import dataclasses
import datetime
import pathlib
import tempfile
from collections.abc import AsyncGenerator

import aiofiles.os
import aioshutil

import atr.db as db
import atr.db.interaction as interaction
import atr.db.models as models
import atr.tasks as tasks
import atr.util as util


@dataclasses.dataclass
class Creating:
    old: models.Revision | None
    interim_path: pathlib.Path
    new: models.Revision | None
    failed: bool = False


# NOTE: The create_directory parameter is not used anymore
# The temporary directory will always be created
@contextlib.asynccontextmanager
async def create_and_manage(
    project_name: str,
    version_name: str,
    asf_uid: str,
    description: str | None = None,
) -> AsyncGenerator[Creating]:
    """Manage the creation and symlinking of a mutable release revision."""
    # Get the release
    release_name = models.release_name(project_name, version_name)
    async with db.session() as data:
        release = await data.release(name=release_name).demand(
            RuntimeError("Release does not exist for new revision creation")
        )
        old_revision = await interaction.latest_revision(release)
    # Create a temporary directory
    # Ensure that it's removed on any exception
    temp_dir: str = await asyncio.to_thread(tempfile.mkdtemp)
    temp_dir_path = pathlib.Path(temp_dir)
    try:
        # The directory was created by mkdtemp, but it's empty
        if old_revision is not None:
            # If this is not the first revision, hard link the previous revision
            old_release_dir = util.release_directory(release)
            await util.create_hard_link_clone(old_release_dir, temp_dir_path, do_not_create_dest_dir=True)
        # The directory is either empty or its files are hard linked to the previous revision
        creating = Creating(old=old_revision, interim_path=temp_dir_path, new=None, failed=False)
        yield creating
    except Exception:
        await aioshutil.rmtree(temp_dir)  # type: ignore[call-arg]
        raise

    if creating.failed:
        await aioshutil.rmtree(temp_dir)  # type: ignore[call-arg]
        return

    # Create a revision row, but hold the write lock
    async with db.session() as data, data.begin():
        new_revision = models.Revision(
            release_name=release_name,
            release=release,
            asfuid=asf_uid,
            created=datetime.datetime.now(datetime.UTC),
            phase=release.phase,
            description=description,
        )
        data.add(new_revision)
        # Flush but do not commit the row to get its name and number
        await data.flush()
        # The row is still invisible to other sessions
        creating.new = new_revision
        # The caller will now have the details about the new revision

        # Rename the directory to the new revision number
        await data.refresh(release)
        new_revision_dir = util.release_directory(release)
        # Ensure that the parent directory exists
        await aiofiles.os.makedirs(new_revision_dir.parent, exist_ok=True)
        # Rename the temporary interim directory to the new revision number
        await aiofiles.os.rename(temp_dir, new_revision_dir)
        # creating.interim_path = None

        # Run checks if in DRAFT phase
        if release.phase == models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
            # Must use caller_data here because we acquired the write lock
            await tasks.draft_checks(project_name, version_name, new_revision.number, caller_data=data)
        # Commit by leaving the data.begin() context manager


async def latest_info(project_name: str, version_name: str) -> tuple[str, str, datetime.datetime] | None:
    """Get the name, editor, and timestamp of the latest revision."""
    release_name = models.release_name(project_name, version_name)
    async with db.session() as data:
        # TODO: No need to get release here
        # Just use maximum seq from revisions
        release = await data.release(name=release_name, _project=True).demand(
            RuntimeError(f"Release {release_name} does not exist")
        )
        if release.latest_revision_number is None:
            return None
        revision = await data.revision(release_name=release_name, number=release.latest_revision_number).get()
        if not revision:
            return None
    return revision.number, revision.asfuid, revision.created
