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

import datetime

import sqlmodel

import atr.db as db
import atr.log as log
import atr.models.sql as sql
import atr.storage as storage


class GeneralPublic:
    def __init__(
        self,
        credentials: storage.WriteAsGeneralPublic,
        write: storage.Write,
        data: db.Session,
    ):
        self.__credentials = credentials
        self.__write = write
        self.__data = data
        self.__asf_uid = write.authorisation.asf_uid


class FoundationCommitter(GeneralPublic):
    def __init__(self, credentials: storage.WriteAsFoundationCommitter, write: storage.Write, data: db.Session):
        super().__init__(credentials, write, data)
        self.__credentials = credentials
        self.__write = write
        self.__data = data
        self.__asf_uid = write.authorisation.asf_uid


class CommitteeParticipant(FoundationCommitter):
    def __init__(
        self,
        credentials: storage.WriteAsCommitteeParticipant,
        write: storage.Write,
        data: db.Session,
        committee_name: str,
    ):
        super().__init__(credentials, write, data)
        self.__credentials = credentials
        self.__write = write
        self.__data = data
        self.__asf_uid = write.authorisation.asf_uid
        self.__committee_name = committee_name


class CommitteeMember(CommitteeParticipant):
    def __init__(
        self,
        credentials: storage.WriteAsCommitteeMember,
        write: storage.Write,
        data: db.Session,
        committee_name: str,
    ):
        super().__init__(credentials, write, data, committee_name)
        self.__credentials = credentials
        self.__write = write
        self.__data = data
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name

    async def ignore_add(
        self,
        release_glob: str | None = None,
        revision_number: str | None = None,
        checker_glob: str | None = None,
        primary_rel_path_glob: str | None = None,
        member_rel_path_glob: str | None = None,
        status: sql.CheckResultStatusIgnore | None = None,
        message_glob: str | None = None,
    ) -> None:
        cri = sql.CheckResultIgnore(
            asf_uid=self.__asf_uid,
            created=datetime.datetime.now(datetime.UTC),
            committee_name=self.__committee_name,
            release_glob=release_glob,
            revision_number=revision_number,
            checker_glob=checker_glob,
            primary_rel_path_glob=primary_rel_path_glob,
            member_rel_path_glob=member_rel_path_glob,
            status=status,
            message_glob=message_glob,
        )
        self.__data.add(cri)
        await self.__data.commit()
        self.__credentials.log_auditable_event(
            action=log.interface_name(),
            asf_uid=self.__asf_uid,
            cri=cri.model_dump_json(exclude_none=True),
        )

    async def ignore_delete(self, id: int) -> None:
        via = sql.validate_instrumented_attribute
        await self.__data.execute(sqlmodel.delete(sql.CheckResultIgnore).where(via(sql.CheckResultIgnore.id) == id))
        await self.__data.commit()
        self.__credentials.log_auditable_event(
            action=log.interface_name(),
            asf_uid=self.__asf_uid,
            ignore_id=id,
        )

    async def ignore_update(
        self,
        id: int,
        release_glob: str | None = None,
        revision_number: str | None = None,
        checker_glob: str | None = None,
        primary_rel_path_glob: str | None = None,
        member_rel_path_glob: str | None = None,
        status: sql.CheckResultStatusIgnore | None = None,
        message_glob: str | None = None,
    ) -> None:
        cri = await self.__data.get(sql.CheckResultIgnore, id)
        if cri is None:
            raise storage.AccessError(f"Ignore {id} not found")
        # The updating ASF UID is now responsible for the whole ignore
        cri.asf_uid = self.__asf_uid
        cri.release_glob = release_glob
        cri.revision_number = revision_number
        cri.checker_glob = checker_glob
        cri.primary_rel_path_glob = primary_rel_path_glob
        cri.member_rel_path_glob = member_rel_path_glob
        cri.status = status
        cri.message_glob = message_glob
        await self.__data.commit()
        self.__credentials.log_auditable_event(
            action=log.interface_name(),
            asf_uid=self.__asf_uid,
            cri=cri.model_dump_json(exclude_none=True),
        )
