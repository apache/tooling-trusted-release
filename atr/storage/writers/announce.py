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
import copy
import datetime
from typing import TYPE_CHECKING

import aiofiles.os
import aioshutil
import sqlmodel

import atr.construct as construct
import atr.db as db
import atr.models.sql as sql
import atr.storage as storage
import atr.tasks.message as message
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

    async def release(
        self,
        project_name: str,
        version_name: str,
        preview_revision_number: str,
        recipient: str,
        subject: str,
        body: str,
        download_path_suffix: str,
        asf_uid: str,
        fullname: str,
    ) -> None:
        if recipient not in util.permitted_recipients(asf_uid):
            raise storage.AccessError(f"You are not permitted to send announcements to {recipient}")

        unfinished_dir: str = ""
        finished_dir: str = ""

        release = await self.__data.release(
            project_name=project_name,
            version=version_name,
            phase=sql.ReleasePhase.RELEASE_PREVIEW,
            latest_revision_number=preview_revision_number,
            _revisions=True,
        ).demand(
            storage.AccessError(
                f"Release {project_name} {version_name} {preview_revision_number} does not exist",
            )
        )
        if (committee := release.project.committee) is None:
            raise storage.AccessError("Release has no committee")

        body = await construct.announce_release_body(
            body,
            options=construct.AnnounceReleaseOptions(
                asfuid=asf_uid,
                fullname=fullname,
                project_name=project_name,
                version_name=version_name,
            ),
        )

        # Prepare paths for file operations
        unfinished_revisions_path = util.release_directory_base(release)
        unfinished_path = unfinished_revisions_path / release.unwrap_revision_number
        unfinished_dir = str(unfinished_path)
        release_date = datetime.datetime.now(datetime.UTC)
        predicted_finished_release = self.__predicted_finished_release(release, release_date)
        finished_path = util.release_directory(predicted_finished_release)
        finished_dir = str(finished_path)
        if await aiofiles.os.path.exists(finished_dir):
            raise storage.AccessError("Release already exists")
        # TODO: This is not reliable because of race conditions
        # But it adds a layer of protection in most cases
        preserve = release.project.policy_preserve_download_files
        if preserve is True:
            await self.__hard_link_downloads(committee, unfinished_path, download_path_suffix, dry_run=True)

        try:
            task = sql.Task(
                status=sql.TaskStatus.QUEUED,
                task_type=sql.TaskType.MESSAGE_SEND,
                task_args=message.Send(
                    email_sender=f"{asf_uid}@apache.org",
                    email_recipient=recipient,
                    subject=subject,
                    body=body,
                    in_reply_to=None,
                ).model_dump(),
                asf_uid=asf_uid,
                project_name=project_name,
                version_name=version_name,
            )
            self.__data.add(task)

            await self.__promote_in_database(release, preview_revision_number, release_date)
            await self.__data.commit()
        except storage.AccessError as e:
            raise e
        except Exception as e:
            raise storage.AccessError(f"Error announcing preview: {e!s}")

        # Ensure that the permissions of every directory are 755
        await asyncio.to_thread(util.chmod_directories, unfinished_path)

        try:
            # Move the release files from somewhere in unfinished to somewhere in finished
            # The whole finished hierarchy is write once for each directory, and then read only
            # TODO: Set permissions to help enforce this, or find alternative methods
            await aioshutil.move(unfinished_dir, finished_dir)
            self.__write_as.append_to_audit_log(
                action="announce.release",
                project_name=project_name,
                version_name=version_name,
                revision_number=preview_revision_number,
                source_directory=unfinished_dir,
                target_directory=finished_dir,
                email_recipient=recipient,
            )
            if unfinished_revisions_path:
                # This removes all of the prior revisions
                await aioshutil.rmtree(str(unfinished_revisions_path))  # type: ignore[call-arg]
        except Exception as e:
            raise storage.AccessError(f"Database updated, but error moving files: {e!s}. Manual cleanup needed.")

        # TODO: Add an audit log entry here
        await self.__hard_link_downloads(
            committee,
            finished_path,
            download_path_suffix,
            preserve=preserve,
        )

    async def __hard_link_downloads(
        self,
        committee: sql.Committee,
        unfinished_path: pathlib.Path,
        download_path_suffix: str,
        dry_run: bool = False,
        preserve: bool = False,
    ) -> None:
        """Hard link the release files to the downloads directory."""
        # TODO: Rename *_dir functions to _path functions
        downloads_base_path = util.get_downloads_dir()
        downloads_path = downloads_base_path / committee.name / download_path_suffix.removeprefix("/")
        # The "exist_ok" parameter means to overwrite files if True
        # We only overwrite if we're not preserving, so we supply "not preserve"
        # TODO: Add a test for this
        await util.create_hard_link_clone(
            unfinished_path,
            downloads_path,
            do_not_create_dest_dir=dry_run,
            exist_ok=not preserve,
            dry_run=dry_run,
        )

    def __predicted_finished_release(self, release: sql.Release, release_date: datetime.datetime) -> sql.Release:
        # Taking a deep copy stops this from being a SQLAlchemy proxy object
        # https://docs.sqlalchemy.org/en/20/orm/session_basics.html
        predicted_finished_release = copy.deepcopy(release)
        predicted_finished_release.phase = sql.ReleasePhase.RELEASE
        predicted_finished_release.released = release_date
        return predicted_finished_release

    async def __promote_in_database(
        self, release: sql.Release, preview_revision_number: str, release_date: datetime.datetime
    ) -> None:
        """Promote a release preview to a release and delete its old revisions."""
        via = sql.validate_instrumented_attribute

        update_stmt = (
            sqlmodel.update(sql.Release)
            .where(
                via(sql.Release.name) == release.name,
                via(sql.Release.phase) == sql.ReleasePhase.RELEASE_PREVIEW,
                sql.latest_revision_number_query() == preview_revision_number,
            )
            .values(
                phase=sql.ReleasePhase.RELEASE,
                released=release_date,
            )
        )
        update_result = await self.__data.execute_query(update_stmt)
        # Avoid a type error with update_result.rowcount
        # Could not find another way to do it, other than using a Protocol
        rowcount: int = getattr(update_result, "rowcount", 0)
        if rowcount != 1:
            raise RuntimeError("A newer revision appeared, please refresh and try again.")

        delete_revisions_stmt = sqlmodel.delete(sql.Revision).where(
            via(sql.Revision.release_name) == release.name,
        )
        await self.__data.execute_query(delete_revisions_stmt)
