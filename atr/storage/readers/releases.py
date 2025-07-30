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

import pathlib
import re

import atr.analysis as analysis
import atr.db as db
import atr.models.sql as sql
import atr.storage as storage
import atr.storage.types as types


class GeneralPublic:
    def __init__(
        self,
        credentials: storage.ReadAsGeneralPublic,
        read: storage.Read,
        data: db.Session,
        asf_uid: str | None = None,
    ):
        self.__credentials = credentials
        self.__read = read
        self.__data = data
        self.__asf_uid = asf_uid

    async def path_info(self, release: sql.Release, paths: list[pathlib.Path]) -> types.PathInfo | None:
        info = types.PathInfo()
        latest_revision_number = release.latest_revision_number
        if latest_revision_number is None:
            return None
        await self.__successes_errors_warnings(release, latest_revision_number, info)
        for path in paths:
            # Get artifacts and metadata
            search = re.search(analysis.extension_pattern(), str(path))
            if search:
                if search.group("artifact"):
                    info.artifacts.add(path)
                elif search.group("metadata"):
                    info.metadata.add(path)
        return info

    async def __successes_errors_warnings(
        self, release: sql.Release, latest_revision_number: str, info: types.PathInfo
    ) -> None:
        # Get successes, warnings, and errors
        successes = await self.__data.check_result(
            release_name=release.name,
            revision_number=latest_revision_number,
            member_rel_path=None,
            status=sql.CheckResultStatus.SUCCESS,
        ).all()
        for success in successes:
            if primary_rel_path := success.primary_rel_path:
                info.successes.setdefault(pathlib.Path(primary_rel_path), []).append(success)

        warnings = await self.__data.check_result(
            release_name=release.name,
            revision_number=latest_revision_number,
            member_rel_path=None,
            status=sql.CheckResultStatus.WARNING,
        ).all()
        for warning in warnings:
            if primary_rel_path := warning.primary_rel_path:
                info.warnings.setdefault(pathlib.Path(primary_rel_path), []).append(warning)

        errors = await self.__data.check_result(
            release_name=release.name,
            revision_number=latest_revision_number,
            member_rel_path=None,
            status=sql.CheckResultStatus.FAILURE,
        ).all()
        for error in errors:
            if primary_rel_path := error.primary_rel_path:
                info.errors.setdefault(pathlib.Path(primary_rel_path), []).append(error)
