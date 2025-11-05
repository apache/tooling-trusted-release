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

import atr.db as db
import atr.models as models
import atr.storage as storage
import atr.util as util


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

    async def edit(self, project_name: str, policy_data: models.policy.ReleasePolicyData) -> None:
        project = await self.__data.project(
            name=project_name, status=models.sql.ProjectStatus.ACTIVE, _release_policy=True
        ).demand(storage.AccessError(f"Project {project_name} not found"))

        release_policy = project.release_policy
        if release_policy is None:
            release_policy = models.sql.ReleasePolicy(project=project)
            project.release_policy = release_policy
            self.__data.add(release_policy)

        # Compose section
        release_policy.source_artifact_paths = policy_data.source_artifact_paths
        release_policy.binary_artifact_paths = policy_data.binary_artifact_paths
        release_policy.github_repository_name = policy_data.github_repository_name
        # TODO: Change to paths, plural
        release_policy.github_compose_workflow_path = policy_data.github_compose_workflow_path
        release_policy.strict_checking = policy_data.strict_checking

        # Vote section
        release_policy.manual_vote = policy_data.manual_vote
        if not release_policy.manual_vote:
            release_policy.github_vote_workflow_path = policy_data.github_vote_workflow_path
            release_policy.mailto_addresses = policy_data.mailto_addresses
            self.__set_default_min_hours(policy_data, project, release_policy)
            release_policy.pause_for_rm = policy_data.pause_for_rm
            release_policy.release_checklist = policy_data.release_checklist
            self.__set_default_start_vote_template(policy_data, project, release_policy)
        elif project.committee and project.committee.is_podling:
            # The caller ensures that project.committee is not None
            raise storage.AccessError("Manual voting is not allowed for podlings.")

        # Finish section
        release_policy.github_finish_workflow_path = policy_data.github_finish_workflow_path
        self.__set_default_announce_release_template(policy_data, project, release_policy)
        release_policy.preserve_download_files = policy_data.preserve_download_files

        await self.__data.commit()

    def __set_default_announce_release_template(
        self,
        policy_data: models.policy.ReleasePolicyData,
        project: models.sql.Project,
        release_policy: models.sql.ReleasePolicy,
    ) -> None:
        submitted_announce_template = policy_data.announce_release_template
        submitted_announce_template = submitted_announce_template.replace("\r\n", "\n")
        rendered_default_announce_hash = policy_data.default_announce_release_template_hash
        current_default_announce_text = project.policy_announce_release_default
        current_default_announce_hash = util.compute_sha3_256(current_default_announce_text.encode())
        submitted_announce_hash = util.compute_sha3_256(submitted_announce_template.encode())

        if (submitted_announce_hash == rendered_default_announce_hash) or (
            submitted_announce_hash == current_default_announce_hash
        ):
            release_policy.announce_release_template = ""
        else:
            release_policy.announce_release_template = submitted_announce_template

    def __set_default_min_hours(
        self,
        policy_data: models.policy.ReleasePolicyData,
        project: models.sql.Project,
        release_policy: models.sql.ReleasePolicy,
    ) -> None:
        submitted_min_hours = policy_data.min_hours
        default_value_seen_on_page_min_hours = policy_data.default_min_hours_value_at_render
        current_system_default_min_hours = project.policy_default_min_hours

        if (
            submitted_min_hours == default_value_seen_on_page_min_hours
            or submitted_min_hours == current_system_default_min_hours
        ):
            release_policy.min_hours = None
        else:
            release_policy.min_hours = submitted_min_hours

    def __set_default_start_vote_template(
        self,
        policy_data: models.policy.ReleasePolicyData,
        project: models.sql.Project,
        release_policy: models.sql.ReleasePolicy,
    ) -> None:
        submitted_start_template = policy_data.start_vote_template
        submitted_start_template = submitted_start_template.replace("\r\n", "\n")
        rendered_default_start_hash = policy_data.default_start_vote_template_hash
        current_default_start_text = project.policy_start_vote_default
        current_default_start_hash = util.compute_sha3_256(current_default_start_text.encode())
        submitted_start_hash = util.compute_sha3_256(submitted_start_template.encode())

        if (submitted_start_hash == rendered_default_start_hash) or (
            submitted_start_hash == current_default_start_hash
        ):
            release_policy.start_vote_template = ""
        else:
            release_policy.start_vote_template = submitted_start_template
