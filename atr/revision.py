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

import contextlib
import datetime
import logging
import pathlib
from collections.abc import AsyncGenerator
from typing import Final

import aiofiles.os

import atr.db as db
import atr.db.models as models
import atr.tasks as tasks
import atr.util as util

_LOGGER: Final = logging.getLogger(__name__)


@contextlib.asynccontextmanager
async def create_and_manage(
    project_name: str, version_name: str, asf_uid: str, preview: bool = False, create_directory: bool = True
) -> AsyncGenerator[tuple[pathlib.Path, str]]:
    """Manage the creation and symlinking of a mutable release revision."""
    base_dir = util.get_unfinished_dir()
    base_release_dir = base_dir / project_name / version_name
    new_revision_name = _new_name(asf_uid)
    new_revision_dir = base_release_dir / new_revision_name

    # Ensure that the base directory for the release exists
    await aiofiles.os.makedirs(base_release_dir, exist_ok=True)

    # Get the parent revision, if available
    parent_revision_id: str | None = None
    parent_revision_dir: pathlib.Path | None = None
    async with db.session() as data:
        release_name = models.release_name(project_name, version_name)
        namespace = release_name + (" draft" if (preview is False) else " preview")
        release = await data.release(name=release_name, _project=True).get()
        if release is not None:
            parent_revision_id = release.revision
            if parent_revision_id:
                parent_revision_dir = base_release_dir / parent_revision_id

    try:
        # Create the new revision directory
        if parent_revision_dir:
            _LOGGER.info(f"Creating new revision {new_revision_name} by hard linking from {parent_revision_id}")
            await util.create_hard_link_clone(parent_revision_dir, new_revision_dir)
        elif create_directory:
            _LOGGER.info(f"Creating new empty revision directory {new_revision_name}")
            await aiofiles.os.makedirs(new_revision_dir)
        else:
            _LOGGER.info(f"Creating new empty revision with no directory for {new_revision_name}")

        # Yield control to the block within "async with"
        yield new_revision_dir, new_revision_name

        # If the "with" block completed without error, store the parent link
        async with db.session() as data:
            async with data.begin():
                if parent_revision_id is not None:
                    _LOGGER.info(f"Storing parent link for {new_revision_name} -> {parent_revision_id}")
                    data.add(models.TextValue(ns=namespace, key=new_revision_name, value=parent_revision_id))
                else:
                    _LOGGER.info(f"No parent revision for {new_revision_name}")
                release = await data.release(name=release_name, _project=True).demand(
                    RuntimeError("Release does not exist")
                )
                release.revision = new_revision_name
        if preview is False:
            # Schedule the checks to be run
            await tasks.draft_checks(project_name, version_name, new_revision_name)

    except Exception:
        _LOGGER.exception(f"Error during revision management for {new_revision_name}")
        # Keep this in case we do clean up the new revision directory
        raise
    finally:
        # TODO: It's hard to know whether we should clean up the new revision directory
        # Generally we should probably keep it no matter what
        # The only exception would be if release.revision was never set
        # But if it wasn't, it doesn't matter so much
        ...


async def latest_info(project_name: str, version_name: str) -> tuple[str | None, str | None, datetime.datetime | None]:
    """Get the name, editor, and timestamp of the latest revision."""
    revision_name: str | None = None
    editor: str | None = None
    timestamp: datetime.datetime | None = None

    async with db.session() as data:
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            RuntimeError("Release does not exist")
        )
        revision_name = release.revision
        if not revision_name:
            return revision_name, editor, timestamp

        parts = revision_name.split("@", 1)
        if len(parts) == 2:
            editor = parts[0]
            dt_obj = datetime.datetime.strptime(parts[1][:-1], "%Y-%m-%dT%H.%M.%S.%f")
            timestamp = dt_obj.replace(tzinfo=datetime.UTC)

    return revision_name, editor, timestamp


def _new_name(asf_uid: str) -> str:
    """Generate a new revision name with timestamp truncated to milliseconds."""
    now_utc = datetime.datetime.now(datetime.UTC)
    time_prefix = now_utc.strftime("%Y-%m-%dT%H.%M.%S")
    milliseconds = now_utc.microsecond // 1000
    timestamp_str = f"{time_prefix}.{milliseconds:03d}Z"
    return f"{asf_uid}@{timestamp_str}"
