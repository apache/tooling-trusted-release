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
    project_name: str,
    version_name: str,
    asf_uid: str,
    create_directory: bool = True,
    description: str | None = None,
) -> AsyncGenerator[tuple[pathlib.Path, str]]:
    """Manage the creation and symlinking of a mutable release revision."""
    base_dir = util.get_unfinished_dir()
    base_release_dir = base_dir / project_name / version_name

    # Ensure that the base directory for the release exists
    await aiofiles.os.makedirs(base_release_dir, exist_ok=True)

    release_name = models.release_name(project_name, version_name)
    # Create and commit the new Revision
    async with db.session() as data:
        release_one = await data.release(name=release_name, _project=True).demand(
            RuntimeError("Release does not exist for new revision creation")
        )

        new_revision = models.Revision(
            # name is automatically computed in an event listener
            release_name=release_one.name,
            release=release_one,
            # seq is automatically computed in an event listener
            # number is automatically computed in an event listener
            asfuid=asf_uid,
            created=datetime.datetime.now(datetime.UTC),
            phase=release_one.phase,
            # parent_name is automatically computed in an event listener
            # parent is automatically computed in an event listener
            child=None,
            description=description,
        )
        data.add(new_revision)
        await data.commit()

        # After commit, new_revision has its .name, .seq, and .number populated by the listener
        new_revision_name = new_revision.name
        new_revision_number = new_revision.number

    if not (new_revision_name and new_revision_number):
        raise RuntimeError("Failed to obtain the name and number of the newly committed revision.")

    # Details needed for directory structure and yield
    parent_revision_dir: pathlib.Path | None = None

    # Get details of the committed revision
    async with db.session() as data:
        new_revision_with_parent = await data.revision(name=new_revision_name, _parent=True).demand(
            RuntimeError("Committed revision not found or parent could not be loaded")
        )
        if new_revision_with_parent.parent:
            parent_revision_dir = base_release_dir / new_revision_with_parent.parent.number

    new_revision_dir = base_release_dir / new_revision_number

    try:
        # Create the new revision directory
        if parent_revision_dir:
            _LOGGER.info(f"Creating new revision {new_revision_number} by hard linking from {parent_revision_dir.name}")
            await util.create_hard_link_clone(parent_revision_dir, new_revision_dir)
        elif create_directory:
            _LOGGER.info(f"Creating new empty revision directory {new_revision_number}")
            await aiofiles.os.makedirs(new_revision_dir)
        else:
            _LOGGER.info(f"Creating new empty revision with no directory for {new_revision_number}")

        # Yield control to the block within "async with"
        yield new_revision_dir, new_revision_number

        # If the release is in the DRAFT phase, schedule the checks to be run
        # The caller may have modified release_one, so we must get it again
        async with db.session() as data:
            release_two = await data.release(name=release_name).demand(
                RuntimeError("Release not found for task scheduling")
            )
            if release_two.phase is models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
                _LOGGER.warning(f"Scheduling checks for {project_name} {version_name} {new_revision_number}")
                # TODO: Passing data=data here breaks the database session
                # Should figure out why that happens
                await tasks.draft_checks(project_name, version_name, new_revision_number)
            else:
                _LOGGER.warning(
                    f"Skipping checks for {project_name} {version_name}"
                    f" {new_revision_number} because release is not in DRAFT phase"
                )

    except Exception:
        _LOGGER.exception(f"Error during revision management for {new_revision_number}")
        # Consider adding cleanup for new_revision_dir if it was created before an error
        raise


async def latest_info(project_name: str, version_name: str) -> tuple[str, str, datetime.datetime] | None:
    """Get the name, editor, and timestamp of the latest revision."""
    async with db.session() as data:
        # TODO: No need to get release here
        # Just use maximum seq from revisions
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            RuntimeError("Release does not exist")
        )
        if release.latest_revision_number is None:
            return None
        revision = await data.revision(release_name=release.name, number=release.latest_revision_number).get()
        if not revision:
            return None
    return revision.number, revision.asfuid, revision.created
