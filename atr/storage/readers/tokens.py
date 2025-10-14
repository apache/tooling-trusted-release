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

import sqlmodel

import atr.db as db
import atr.models.sql as sql
import atr.storage as storage


class GeneralPublic:
    def __init__(self, read: storage.Read, read_as: storage.ReadAsGeneralPublic, data: db.Session):
        self.__read = read
        self.__read_as = read_as
        self.__data = data
        self.__asf_uid = read.authorisation.asf_uid


class FoundationCommitter(GeneralPublic):
    def __init__(self, read: storage.Read, read_as: storage.ReadAsFoundationCommitter, data: db.Session):
        super().__init__(read, read_as, data)
        self.__read = read
        self.__read_as = read_as
        self.__data = data

    async def own_personal_access_tokens(self) -> list[sql.PersonalAccessToken]:
        asf_uid = self.__read.authorisation.asf_uid
        if asf_uid is None:
            raise ValueError("An ASF UID is required")
        via = sql.validate_instrumented_attribute
        stmt = (
            sqlmodel.select(sql.PersonalAccessToken)
            .where(sql.PersonalAccessToken.asfuid == asf_uid)
            .order_by(via(sql.PersonalAccessToken.created))
        )
        return await self.__data.query_all(stmt)

    async def most_recent_jwt_pat(self) -> sql.PersonalAccessToken | None:
        # , asf_uid: str | None = None
        # if asf_uid is None:
        asf_uid = self.__read.authorisation.asf_uid
        if asf_uid is None:
            raise ValueError("An ASF UID is required")
        via = sql.validate_instrumented_attribute
        stmt = (
            sqlmodel.select(sql.PersonalAccessToken)
            .where(sql.PersonalAccessToken.asfuid == asf_uid)
            .where(via(sql.PersonalAccessToken.last_used).is_not(None))
            .order_by(via(sql.PersonalAccessToken.last_used).desc())
            .limit(1)
        )
        return await self.__data.query_one_or_none(stmt)
