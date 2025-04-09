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

import aiofiles.os
import aioshutil

import atr.db as db
import atr.db.models as models
import atr.tasks as tasks
import atr.util as util

_LOGGER = logging.getLogger(__name__)


@contextlib.asynccontextmanager
async def create_and_manage(
    project_name: str, version_name: str, asf_uid: str
) -> AsyncGenerator[tuple[pathlib.Path, str]]:
    """Manage the creation and symlinking of a draft release candidate revision."""
    draft_base_dir = util.get_release_candidate_draft_dir()
    release_dir = draft_base_dir / project_name / version_name
    latest_symlink_path = release_dir / "latest"
    new_revision_name = _new_name(asf_uid)
    new_revision_dir = release_dir / new_revision_name

    # Ensure that the base directory for the release exists
    await aiofiles.os.makedirs(release_dir, exist_ok=True)

    # Check for the parent revision
    parent_revision_dir, parent_revision_id = await _manage_draft_revision_find_parent(release_dir, latest_symlink_path)

    temp_dir_created = False
    try:
        # Create the new revision directory
        if parent_revision_dir:
            _LOGGER.info(f"Creating new revision {new_revision_name} by hard-linking from {parent_revision_id}")
            await util.create_hard_link_clone(parent_revision_dir, new_revision_dir)
        else:
            _LOGGER.info(f"Creating new empty revision directory {new_revision_name}")
            await aiofiles.os.makedirs(new_revision_dir)
        temp_dir_created = True

        # Yield control to the block within "async with"
        yield new_revision_dir, new_revision_name

        # If the "with" block completed without error, store the parent link
        if parent_revision_id is not None:
            _LOGGER.info(f"Storing parent link for {new_revision_name} -> {parent_revision_id}")
            try:
                async with db.session() as data:
                    async with data.begin():
                        data.add(models.TextValue(ns="draft_parent", key=new_revision_name, value=parent_revision_id))
            except Exception as db_e:
                _LOGGER.error(f"Failed to store parent link for {new_revision_name}: {db_e}")
                # Raise again to ensure clean up in the finally block
                raise

        _LOGGER.info(f'Updating "latest" symlink to point to {new_revision_name}')
        # Target must be relative for the symlink to work correctly within the release directory
        await util.update_atomic_symlink(latest_symlink_path, new_revision_name)
        # Schedule the checks to be run
        await tasks.draft_checks(project_name, version_name, new_revision_name)

    except Exception:
        _LOGGER.exception(f"Error during draft revision management for {new_revision_name}, cleaning up")
        # Raise the exception again after the clean up attempt
        raise
    finally:
        # Clean up only if an error occurred during the "with" block or initial setup
        # Check whether new_revision_dir exists and whether we should remove it
        if temp_dir_created:
            # Determine whether an exception occurred within the "with" block
            # We just check whether the symlink was updated
            should_clean_up = True
            if await aiofiles.os.path.islink(latest_symlink_path):
                try:
                    target = await aiofiles.os.readlink(str(latest_symlink_path))
                    if target == new_revision_name:
                        # Symlink points to the new dir, assume success
                        should_clean_up = False
                except OSError:
                    # Error reading link, proceed with clean up
                    ...

            if should_clean_up:
                _LOGGER.warning(f"Cleaning up potentially incomplete revision directory: {new_revision_dir}")
                with contextlib.suppress(Exception):
                    # Prevent clean_up errors from masking original exception
                    await aioshutil.rmtree(new_revision_dir)  # type: ignore[call-arg]


async def latest_info(project_name: str, version_name: str) -> tuple[str | None, datetime.datetime | None]:
    """Get the editor and timestamp of the latest revision from the filesystem."""
    editor: str | None = None
    timestamp: datetime.datetime | None = None

    with contextlib.suppress(OSError, FileNotFoundError, ValueError):
        draft_base_dir = util.get_release_candidate_draft_dir()
        release_dir = draft_base_dir / project_name / version_name
        latest_symlink_path = release_dir / "latest"

        if await aiofiles.os.path.islink(latest_symlink_path):
            revision_name = await aiofiles.os.readlink(str(latest_symlink_path))
            parts = revision_name.split("@", 1)
            if len(parts) == 2:
                editor = parts[0]
                dt_obj = datetime.datetime.strptime(parts[1][:-1], "%Y-%m-%dT%H.%M.%S.%f")
                timestamp = dt_obj.replace(tzinfo=datetime.UTC)

    return editor, timestamp


async def _manage_draft_revision_find_parent(
    release_dir: pathlib.Path, latest_symlink_path: pathlib.Path
) -> tuple[pathlib.Path | None, str | None]:
    """Check for and validate the parent revision based on the "latest" symlink."""
    parent_revision_dir: pathlib.Path | None = None
    parent_revision_id: str | None = None

    if await aiofiles.os.path.islink(latest_symlink_path):
        try:
            target = await aiofiles.os.readlink(str(latest_symlink_path))
            # Assume target is relative to release_dir
            potential_parent_dir = (release_dir / target).resolve()
            if await aiofiles.os.path.isdir(potential_parent_dir):
                parent_revision_dir = potential_parent_dir
                parent_revision_id = potential_parent_dir.name
                _LOGGER.info(f'Found existing "latest" pointing to parent revision: {parent_revision_id}')
            else:
                _LOGGER.warning(f'A "latest" symlink exists but points to non-directory: {target}, treating as new')
        except OSError as e:
            _LOGGER.warning(f'Error reading "latest" symlink: {e}, treating as new')

    return parent_revision_dir, parent_revision_id


def _new_name(asf_uid: str) -> str:
    """Generate a new revision name with timestamp truncated to milliseconds."""
    now_utc = datetime.datetime.now(datetime.UTC)
    time_prefix = now_utc.strftime("%Y-%m-%dT%H.%M.%S")
    milliseconds = now_utc.microsecond // 1000
    timestamp_str = f"{time_prefix}.{milliseconds:03d}Z"
    return f"{asf_uid}@{timestamp_str}"
