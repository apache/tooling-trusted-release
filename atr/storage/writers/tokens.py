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
import hashlib

import sqlmodel

import atr.db as db
import atr.jwtoken as jwtoken
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
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid

    async def add_token(
        self, uid: str, token_hash: str, created: datetime.datetime, expires: datetime.datetime, label: str | None
    ) -> sql.PersonalAccessToken:
        pat = sql.PersonalAccessToken(
            asfuid=uid,
            token_hash=token_hash,
            created=created,
            expires=expires,
            label=label,
        )
        self.__data.add(pat)
        await self.__data.commit()
        return pat

    async def issue_jwt(self, pat_text: str) -> str:
        pat_hash = hashlib.sha3_256(pat_text.encode()).hexdigest()
        pat = await self.__data.query_one_or_none(
            sqlmodel.select(sql.PersonalAccessToken).where(
                sql.PersonalAccessToken.asfuid == self.__asf_uid,
                sql.PersonalAccessToken.token_hash == pat_hash,
            )
        )
        if pat is None:
            raise storage.AccessError("Invalid PAT")
        if pat.expires < datetime.datetime.now(datetime.UTC):
            raise storage.AccessError("Expired PAT")
        issued_jwt = jwtoken.issue(self.__asf_uid)
        pat.last_used = datetime.datetime.now(datetime.UTC)
        await self.__data.commit()
        self.__credentials.log_auditable_event(
            action=log.interface_name(),
            asf_uid=self.__asf_uid,
            pat_hash=pat_hash,
        )
        return issued_jwt


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
