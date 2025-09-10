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

import atr.db as db
import atr.models.sql as sql
import atr.revision as revision
import atr.storage as storage
import atr.util as util


class GeneralPublic:
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsGeneralPublic,
        data: db.Session,
    ) -> None:
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        self.__asf_uid = write.authorisation.asf_uid


class FoundationCommitter(GeneralPublic):
    def __init__(self, write: storage.Write, write_as: storage.WriteAsFoundationCommitter, data: db.Session) -> None:
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
    ) -> None:
        super().__init__(write, write_as, data)
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name

    async def start(self, project_name: str, version: str) -> tuple[sql.Release, sql.Project]:
        """Creates the initial release draft record and revision directory."""
        # Get the project from the project name
        project = await self.__data.project(name=project_name, status=sql.ProjectStatus.ACTIVE, _committee=True).get()
        if not project:
            raise storage.AccessError(f"Project {project_name} not found")

        # TODO: Temporarily allow committers to start drafts
        if project.committee is None or (
            self.__asf_uid not in project.committee.committee_members
            and self.__asf_uid not in project.committee.committers
        ):
            raise storage.AccessError(
                f"You must be a member or committer for the {project.display_name} committee to start a release draft."
            )

        # TODO: Consider using Release.revision instead of ./latest
        # Check whether the release already exists
        if release := await self.__data.release(project_name=project.name, version=version).get():
            if release.phase == sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
                raise storage.AccessError(f"A draft for {project_name} {version} already exists.")
            else:
                raise storage.AccessError(
                    f"A release ({release.phase.value}) for {project_name} {version} already exists."
                )

        # Validate the version name
        # TODO: We should check that it's bigger than the current version
        # We have the packaging library as a dependency, but it is Python specific
        if version_name_error := util.version_name_error(version):
            raise storage.AccessError(f'Invalid version name "{version}": {version_name_error}')

        release = sql.Release(
            phase=sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
            project_name=project.name,
            project=project,
            version=version,
            created=datetime.datetime.now(datetime.UTC),
        )
        self.__data.add(release)
        await self.__data.commit()
        await self.__data.refresh(release)

        description = "Creation of empty release candidate draft through web interface"
        async with revision.create_and_manage(
            project_name, version, self.__asf_uid, description=description
        ) as _creating:
            pass
        return release, project


class CommitteeMember(CommitteeParticipant):
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsCommitteeMember,
        data: db.Session,
        committee_name: str,
    ) -> None:
        super().__init__(write, write_as, data, committee_name)
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name
