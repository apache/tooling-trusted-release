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

# Removing this will cause circular imports
from __future__ import annotations

import asyncio
import contextlib
import datetime
import pathlib
import secrets
import tempfile
from typing import TYPE_CHECKING

import aiofiles.os
import aioshutil

import atr.db as db
import atr.db.interaction as interaction
import atr.models.sql as sql
import atr.storage as storage
import atr.storage.types as types
import atr.tasks as tasks
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


class SafeSession:
    def __init__(self, temp_dir: str):
        self._stack = contextlib.AsyncExitStack()
        self._manager = db.session()
        self._temp_dir = temp_dir

    async def __aenter__(self) -> db.Session:
        try:
            return await self._stack.enter_async_context(self._manager)
        except Exception:
            await aioshutil.rmtree(self._temp_dir)  # type: ignore[call-arg]
            raise

    async def __aexit__(self, _exc_type, _exc, _tb):
        await self._stack.aclose()
        return False


class GeneralPublic:
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsGeneralPublic,
        data: db.Session,
    ):
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        self.__asf_uid = write.authorisation.asf_uid


class FoundationCommitter(GeneralPublic):
    def __init__(self, write: storage.Write, write_as: storage.WriteAsFoundationCommitter, data: db.Session):
        super().__init__(write, write_as, data)
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid


class CommitteeParticipant(FoundationCommitter):
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsCommitteeParticipant,
        data: db.Session,
        committee_name: str,
    ):
        super().__init__(write, write_as, data)
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name

    @contextlib.asynccontextmanager
    async def create_and_manage(
        self,
        project_name: str,
        version_name: str,
        asf_uid: str,
        description: str | None = None,
    ) -> AsyncGenerator[types.Creating]:
        """Manage the creation and symlinking of a mutable release revision."""
        # Get the release
        release_name = sql.release_name(project_name, version_name)
        async with db.session() as data:
            release = await data.release(name=release_name).demand(
                RuntimeError("Release does not exist for new revision creation")
            )
            old_revision = await interaction.latest_revision(release)

        # Create a temporary directory
        # We ensure, below, that it's removed on any exception
        # Use the tmp subdirectory of state, to ensure that it is on the same filesystem
        prefix_token = secrets.token_hex(16)
        temp_dir: str = await asyncio.to_thread(tempfile.mkdtemp, prefix=prefix_token + "-", dir=util.get_tmp_dir())
        temp_dir_path = pathlib.Path(temp_dir)
        creating = types.Creating(old=old_revision, interim_path=temp_dir_path, new=None, failed=None)
        try:
            # The directory was created by mkdtemp, but it's empty
            if old_revision is not None:
                # If this is not the first revision, hard link the previous revision
                old_release_dir = util.release_directory(release)
                await util.create_hard_link_clone(old_release_dir, temp_dir_path, do_not_create_dest_dir=True)
            # The directory is either empty or its files are hard linked to the previous revision
            yield creating
        except types.FailedError as e:
            await aioshutil.rmtree(temp_dir)  # type: ignore[call-arg]
            creating.failed = e
            return
        except Exception:
            await aioshutil.rmtree(temp_dir)  # type: ignore[call-arg]
            raise

        # Ensure that the permissions of every directory are 755
        try:
            await asyncio.to_thread(util.chmod_directories, temp_dir_path)
        except Exception:
            await aioshutil.rmtree(temp_dir)  # type: ignore[call-arg]
            raise

        async with SafeSession(temp_dir) as data:
            try:
                # This is the only place where models.Revision is constructed
                # That makes models.populate_revision_sequence_and_name safe against races
                # Because that event is called when data.add is called below
                # And we have a write lock at that point through the use of data.begin_immediate
                new_revision = sql.Revision(
                    release_name=release_name,
                    release=release,
                    asfuid=asf_uid,
                    created=datetime.datetime.now(datetime.UTC),
                    phase=release.phase,
                    description=description,
                )

                # Acquire the write lock and add the row
                # We need this write lock for moving the directory below atomically
                # But it also helps to make models.populate_revision_sequence_and_name safe against races
                await data.begin_immediate()
                data.add(new_revision)

                # Flush but do not commit the new revision row to get its name and number
                # The row will still be invisible to other sessions after flushing
                await data.flush()
                # Give the caller details about the new revision
                creating.new = new_revision

                # Rename the directory to the new revision number
                await data.refresh(release)
                new_revision_dir = util.release_directory(release)

                # Ensure that the parent directory exists
                await aiofiles.os.makedirs(new_revision_dir.parent, exist_ok=True)

                # Rename the temporary interim directory to the new revision number
                await aiofiles.os.rename(temp_dir, new_revision_dir)
            except Exception:
                await aioshutil.rmtree(temp_dir)  # type: ignore[call-arg]
                raise

            # Commit to end the transaction started by data.begin_immediate
            # We must commit the revision before starting the checks
            # This also releases the write lock
            await data.commit()

            async with data.begin():
                # Run checks if in DRAFT phase
                # We could also run this outside the data Session
                # But then it would create its own new Session
                # It does, however, need a transaction to be created using data.begin()
                if release.phase == sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
                    # Must use caller_data here because we acquired the write lock
                    await tasks.draft_checks(asf_uid, project_name, version_name, new_revision.number, caller_data=data)


class CommitteeMember(CommitteeParticipant):
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsCommitteeMember,
        data: db.Session,
        committee_name: str,
    ):
        super().__init__(write, write_as, data, committee_name)
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name
