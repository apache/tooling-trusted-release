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
import datetime
from typing import TYPE_CHECKING

import atr.db as db
import atr.models.sql as sql
import atr.storage as storage
import atr.tasks.sbom as sbom
import atr.util as util

if TYPE_CHECKING:
    import pathlib


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

    async def generate_cyclonedx(
        self,
        project_name: str,
        version_name: str,
        revision_number: str,
        path_in_new_revision: pathlib.Path,
        sbom_path_in_new_revision: pathlib.Path,
    ) -> sql.Task:
        # Create and queue the task, using paths within the new revision
        # TODO: Move this to the storage interface
        # We still need release.name for the task metadata
        sbom_task = sql.Task(
            task_type=sql.TaskType.SBOM_GENERATE_CYCLONEDX,
            task_args=sbom.GenerateCycloneDX(
                artifact_path=str(path_in_new_revision.resolve()),
                output_path=str(sbom_path_in_new_revision.resolve()),
            ).model_dump(),
            asf_uid=util.unwrap(self.__asf_uid),
            added=datetime.datetime.now(datetime.UTC),
            status=sql.TaskStatus.QUEUED,
            project_name=project_name,
            version_name=version_name,
            revision_number=revision_number,
        )
        self.__data.add(sbom_task)
        await self.__data.commit()
        await self.__data.refresh(sbom_task)
        return sbom_task

    # TODO: This is not a writer
    # Move this to the readers
    async def generate_cyclonedx_wait(self, sbom_task: sql.Task) -> None:
        # We must wait until the sbom_task is complete before we can queue checks
        # Maximum wait time is 60 * 100ms = 6000ms
        for _attempt in range(60):
            await self.__data.refresh(sbom_task)
            if sbom_task.status != sql.TaskStatus.QUEUED:
                break
            # Wait 100ms before checking again
            await asyncio.sleep(0.1)


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
