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

import sqlite3
from typing import TYPE_CHECKING

import sqlalchemy.exc as exc

import atr.db as db
import atr.models.sql as sql
import atr.storage as storage

if TYPE_CHECKING:
    import datetime


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
        self.__asf_uid = write.authorisation.asf_uid
        self.__committee_name = committee_name


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

    async def add_distribution(
        self,
        release_name: str,
        platform: sql.DistributionPlatform,
        owner_namespace: str | None,
        package: str,
        version: str,
        staging: bool,
        upload_date: datetime.datetime | None,
        api_url: str,
    ) -> tuple[sql.Distribution, bool]:
        distribution = sql.Distribution(
            platform=platform,
            release_name=release_name,
            owner_namespace=owner_namespace or "",
            package=package,
            version=version,
            staging=staging,
            upload_date=upload_date,
            api_url=api_url,
        )
        self.__data.add(distribution)
        try:
            await self.__data.commit()
        except exc.IntegrityError as e:
            # "The names and numeric values for existing result codes are fixed and unchanging."
            # https://www.sqlite.org/rescode.html
            # e.orig.sqlite_errorcode == 1555
            # e.orig.sqlite_errorname == "SQLITE_CONSTRAINT_PRIMARYKEY"
            match e.orig:
                case sqlite3.IntegrityError(sqlite_errorcode=sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY):
                    if not staging:
                        upgraded = await self.__upgrade_staging_to_final(
                            release_name,
                            platform,
                            owner_namespace,
                            package,
                            version,
                            upload_date,
                            api_url,
                        )
                        if upgraded is not None:
                            return upgraded, False
                    return distribution, False
            raise e
        return distribution, True

    async def __upgrade_staging_to_final(
        self,
        release_name: str,
        platform: sql.DistributionPlatform,
        owner_namespace: str | None,
        package: str,
        version: str,
        upload_date: datetime.datetime | None,
        api_url: str,
    ) -> sql.Distribution | None:
        tag = f"{release_name} {platform} {owner_namespace or ''} {package} {version}"
        existing = await self.__data.distribution(
            release_name=release_name,
            platform=platform,
            owner_namespace=(owner_namespace or ""),
            package=package,
            version=version,
        ).demand(RuntimeError(f"Distribution {tag} not found"))
        if existing.staging:
            existing.staging = False
            existing.upload_date = upload_date
            existing.api_url = api_url
            await self.__data.commit()
            return existing
        return None

    async def delete_distribution(
        self,
        release_name: str,
        platform: sql.DistributionPlatform,
        owner_namespace: str,
        package: str,
        version: str,
    ) -> None:
        distribution = await self.__data.distribution(
            release_name=release_name,
            platform=platform,
            owner_namespace=owner_namespace,
            package=package,
            version=version,
        ).demand(
            RuntimeError(f"Distribution {release_name} {platform} {owner_namespace} {package} {version} not found")
        )
        await self.__data.delete(distribution)
        await self.__data.commit()
