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

import atr.construct as construct
import atr.db as db
import atr.db.interaction as interaction
import atr.log as log
import atr.models.sql as sql
import atr.revision as revision
import atr.storage as storage
import atr.tasks.message as message
import atr.tasks.vote as tasks_vote
import atr.user as user
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

    async def resolve(
        self,
        project_name: str,
        version_name: str,
        vote_result: Literal["passed", "failed"],
        asf_fullname: str,
        resolution_body: str,
    ) -> tuple[sql.Release, int | None, str, str | None]:
        release = await self.__data.release(
            name=sql.release_name(project_name, version_name),
            phase=sql.ReleasePhase.RELEASE_CANDIDATE,
            _project=True,
            _committee=True,
        ).demand(storage.AccessError("Release not found"))

        is_podling = False
        if release.project.committee is not None:
            is_podling = release.project.committee.is_podling
        podling_thread_id = release.podling_thread_id

        latest_vote_task = await interaction.release_latest_vote_task(release)
        if latest_vote_task is None:
            raise RuntimeError("No vote task found, unable to send resolution message.")

        voting_round = None
        if is_podling is True:
            voting_round = 1 if (podling_thread_id is None) else 2
        if release.committee is None:
            raise ValueError("Project has no committee")

        return await self.resolve_release(
            project_name,
            release,
            voting_round,
            vote_result,
            latest_vote_task,
            asf_fullname,
            resolution_body,
        )

    async def resolve_release(
        self,
        project_name: str,
        release: sql.Release,
        voting_round: int | None,
        vote_result: Literal["passed", "failed"],
        latest_vote_task: sql.Task,
        asf_fullname: str,
        resolution_body: str,
    ) -> tuple[sql.Release, int | None, str, str | None]:
        # Attach the existing release to the session
        release = await self.__data.merge(release)
        # Update the release phase based on vote result
        extra_destination = None
        if (voting_round == 1) and (vote_result == "passed"):
            # This is the first podling vote, by the PPMC and not the Incubator PMC
            # In this branch, we do not move to RELEASE_PREVIEW but keep everything the same
            # We only set the podling_thread_id to the thread_id of the vote thread
            # Then we automatically start the Incubator PMC vote
            # TODO: Note on the resolve vote page that resolving the Project PPMC vote starts the Incubator PMC vote
            task_mid = interaction.task_mid_get(latest_vote_task)
            archive_url = await interaction.task_archive_url_cached(task_mid)
            if archive_url is None:
                raise ValueError("No archive URL found for podling vote")
            thread_id = archive_url.split("/")[-1]
            release.podling_thread_id = thread_id
            # incubator_vote_address = "general@incubator.apache.org"
            incubator_vote_address = util.USER_TESTS_ADDRESS
            if not release.project.committee:
                raise ValueError("Project has no committee")
            revision_number = release.latest_revision_number
            if revision_number is None:
                raise ValueError("Release has no revision number")
            await self.start(
                email_to=incubator_vote_address,
                permitted_recipients=[incubator_vote_address],
                project_name=release.project.name,
                version_name=release.version,
                selected_revision_number=revision_number,
                asf_uid=self.__asf_uid,
                asf_fullname=asf_fullname,
                vote_duration_choice=latest_vote_task.task_args["vote_duration"],
                subject_data=f"[VOTE] Release {release.project.display_name} {release.version}",
                body_data=await construct.start_vote_default(release.project.name),
                release=release,
                promote=False,
            )
            success_message = "Project PPMC vote marked as passed, and Incubator PMC vote automatically started"
        elif vote_result == "passed":
            release.phase = sql.ReleasePhase.RELEASE_PREVIEW
            success_message = "Vote marked as passed"

            description = "Create a preview revision from the last candidate draft"
            async with revision.create_and_manage(
                project_name, release.version, self.__asf_uid, description=description
            ) as _creating:
                pass
            if (voting_round == 2) and (release.podling_thread_id is not None):
                round_one_email_address, round_one_message_id = await util.email_mid_from_thread_id(
                    release.podling_thread_id
                )
                extra_destination = (round_one_email_address, round_one_message_id)
        else:
            release.phase = sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
            success_message = "Vote marked as failed"
        await self.__data.commit()

        error_message = await self.send_resolution(
            release,
            vote_result,
            resolution_body,
            self.__asf_uid,
            asf_fullname,
            latest_vote_task,
            extra_destination=extra_destination,
        )
        return release, voting_round, success_message, error_message

    async def send_resolution(
        self,
        release: sql.Release,
        resolution: str,
        body: str,
        asf_uid: str,
        asf_fullname: str,
        latest_vote_task: sql.Task,
        extra_destination: tuple[str, str] | None = None,
    ) -> str | None:
        # Get the email thread
        vote_thread_mid = interaction.task_mid_get(latest_vote_task)
        if vote_thread_mid is None:
            return "No vote thread found, unable to send resolution message."

        # Construct the reply email
        # original_subject = latest_vote_task.task_args["subject"]

        # Arguments for the task to cast a vote
        email_recipient = latest_vote_task.task_args["email_to"]
        email_sender = f"{asf_uid}@apache.org"
        subject = f"[VOTE] [RESULT] Release {release.project.display_name} {release.version} {resolution.upper()}"
        signature = f"-- \n{asf_fullname} ({asf_uid})"
        if asf_fullname == asf_uid:
            signature = f"-- \n{asf_fullname}"
        body = f"{body}\n\n{signature}"
        in_reply_to = vote_thread_mid

        task = sql.Task(
            status=sql.TaskStatus.QUEUED,
            task_type=sql.TaskType.MESSAGE_SEND,
            task_args=message.Send(
                email_sender=email_sender,
                email_recipient=email_recipient,
                subject=subject,
                body=body,
                in_reply_to=in_reply_to,
            ).model_dump(),
            asf_uid=asf_uid,
            project_name=release.project.name,
            version_name=release.version,
        )
        tasks = [task]
        if extra_destination is not None:
            task = sql.Task(
                status=sql.TaskStatus.QUEUED,
                task_type=sql.TaskType.MESSAGE_SEND,
                task_args=message.Send(
                    email_sender=email_sender,
                    email_recipient=extra_destination[0],
                    subject=subject,
                    body=body,
                    in_reply_to=extra_destination[1],
                ).model_dump(),
                asf_uid=asf_uid,
                project_name=release.project.name,
                version_name=release.version,
            )
            tasks.append(task)
        self.__data.add_all(tasks)
        await self.__data.flush()
        await self.__data.commit()
        return None

    async def start(
        self,
        email_to: str,
        project_name: str,
        version_name: str,
        selected_revision_number: str,
        vote_duration_choice: int,
        subject_data: str,
        body_data: str,
        asf_uid: str,
        asf_fullname: str,
        release: sql.Release | None = None,
        promote: bool = True,
        permitted_recipients: list[str] | None = None,
    ) -> sql.Task:
        if release is None:
            release = await self.__data.release(
                project_name=project_name,
                version=version_name,
                _project=True,
                _committee=True,
            ).demand(storage.AccessError("Release not found"))
        if permitted_recipients is None:
            permitted_recipients = util.permitted_recipients(asf_uid)
        if email_to not in permitted_recipients:
            # This will be checked again by tasks/vote.py for extra safety
            log.info(f"Invalid mailing list choice: {email_to} not in {permitted_recipients}")
            raise storage.AccessError("Invalid mailing list choice")

        if promote is True:
            # This verifies the state and sets the phase to RELEASE_CANDIDATE
            error = await interaction.promote_release(
                self.__data, release.name, selected_revision_number, vote_manual=False
            )
            if error:
                raise storage.AccessError(error)

        # TODO: We also need to store the duration of the vote
        # We can't allow resolution of the vote until the duration has elapsed
        # But we allow the user to specify in the form
        # And yet we also have ReleasePolicy.min_hours
        # Presumably this sets the default, and the form takes precedence?
        # ReleasePolicy.min_hours can also be 0, though

        # Create a task for vote initiation
        task = sql.Task(
            status=sql.TaskStatus.QUEUED,
            task_type=sql.TaskType.VOTE_INITIATE,
            task_args=tasks_vote.Initiate(
                release_name=release.name,
                email_to=email_to,
                vote_duration=vote_duration_choice,
                initiator_id=asf_uid,
                initiator_fullname=asf_fullname,
                subject=subject_data,
                body=body_data,
            ).model_dump(),
            asf_uid=asf_uid,
            project_name=project_name,
            version_name=version_name,
        )
        self.__data.add(task)
        await self.__data.commit()

        # TODO: We should log all outgoing email and the session so that users can confirm
        # And can be warned if there was a failure
        # (The message should be shown on the vote resolution page)
        return task

    def __committee_member_or_admin(self, committee: sql.Committee, asf_uid: str) -> None:
        if not (user.is_committee_member(committee, asf_uid) or user.is_admin(asf_uid)):
            raise storage.AccessError("You do not have permission to perform this action")
