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

from typing import Literal

import atr.db as db
import atr.db.interaction as interaction
import atr.models.sql as sql
import atr.revision as revision
import atr.storage as storage
import atr.tasks.vote as tasks_vote
import atr.user as user


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

    async def resolve(self, project_name: str, version_name: str, resolution: Literal["passed", "failed"]) -> None:
        release_name = sql.release_name(project_name, version_name)
        release = await self.__data.release(name=release_name, _project=True, _committee=True).demand(
            storage.AccessError("Release not found")
        )
        if release.project.committee is None:
            raise storage.AccessError("Project has no committee")
        self.__committee_member_or_admin(release.project.committee, self.__asf_uid)

        release = await self.__data.merge(release)
        match resolution:
            case "passed":
                release.phase = sql.ReleasePhase.RELEASE_PREVIEW
                description = "Create a preview revision from the last candidate draft"
                async with revision.create_and_manage(
                    project_name, release.version, self.__asf_uid, description=description
                ) as _creating:
                    pass
            case "failed":
                release.phase = sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
        await self.__data.commit()

    async def start(
        self,
        project_name: str,
        version_name: str,
        revision_number: str,
        email_to: str,
        vote_duration: int,
        subject: str,
        body: str,
    ) -> sql.Task:
        release_name = sql.release_name(project_name, version_name)
        release = await self.__data.release(name=release_name, _project=True, _committee=True).demand(
            storage.AccessError("Release not found")
        )
        if release.project.committee is None:
            raise storage.AccessError("Project has no committee")
        self.__committee_member_or_admin(release.project.committee, self.__asf_uid)

        revision_exists = await self.__data.revision(release_name=release_name, number=revision_number).get()
        if revision_exists is None:
            raise storage.AccessError(f"Revision '{revision_number}' does not exist")

        error = await interaction.promote_release(self.__data, release_name, revision_number, vote_manual=False)
        if error:
            raise storage.AccessError(error)

        # TODO: Move this into a function in routes/voting.py
        task = sql.Task(
            status=sql.TaskStatus.QUEUED,
            task_type=sql.TaskType.VOTE_INITIATE,
            task_args=tasks_vote.Initiate(
                release_name=release_name,
                email_to=email_to,
                vote_duration=vote_duration,
                initiator_id=self.__asf_uid,
                initiator_fullname=self.__asf_uid,
                subject=subject,
                body=body,
            ).model_dump(),
            asf_uid=self.__asf_uid,
            project_name=project_name,
            version_name=version_name,
        )
        self.__data.add(task)
        await self.__data.commit()
        return task

    def __committee_member_or_admin(self, committee: sql.Committee, asf_uid: str) -> None:
        if not (user.is_committee_member(committee, asf_uid) or user.is_admin(asf_uid)):
            raise storage.AccessError("You do not have permission to perform this action")
