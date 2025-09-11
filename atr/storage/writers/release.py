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

import base64
import contextlib
import datetime
import pathlib
from typing import TYPE_CHECKING

import aiofiles.os
import aioshutil

import atr.analysis as analysis
import atr.db as db
import atr.log as log
import atr.models.api as api
import atr.models.sql as sql
import atr.revision as revision
import atr.storage as storage
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


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

    @contextlib.asynccontextmanager
    async def create_and_manage_revision(
        self, project_name: str, version: str, description: str
    ) -> AsyncGenerator[revision.Creating]:
        async with revision.create_and_manage(
            project_name, version, self.__asf_uid, description=description
        ) as _creating:
            yield _creating

    async def delete_empty_directory(
        self, project_name: str, version_name: str, dir_to_delete_rel: pathlib.Path
    ) -> str | None:
        description = f"Delete empty directory {dir_to_delete_rel} via web interface"
        async with self.create_and_manage_revision(project_name, version_name, description) as creating:
            path_to_remove = creating.interim_path / dir_to_delete_rel
            path_to_remove.resolve().relative_to(creating.interim_path.resolve())
            if not await aiofiles.os.path.isdir(path_to_remove):
                raise revision.FailedError(f"Path '{dir_to_delete_rel}' is not a directory.")
            if await aiofiles.os.listdir(path_to_remove):
                raise revision.FailedError(f"Directory '{dir_to_delete_rel}' is not empty.")
            # TODO: Move to the storage interface
            await aiofiles.os.rmdir(path_to_remove)
        if creating.failed is not None:
            return str(creating.failed)
        return None

    async def delete_file(self, project_name: str, version: str, rel_path_to_delete: pathlib.Path) -> int:
        metadata_files_deleted = 0
        description = "File deletion through web interface"
        async with self.create_and_manage_revision(project_name, version, description) as creating:
            # Uses new_revision_number for logging only
            # Path to delete within the new revision directory
            path_in_new_revision = creating.interim_path / rel_path_to_delete

            # Check that the file exists in the new revision
            if not await aiofiles.os.path.exists(path_in_new_revision):
                # This indicates a potential severe issue with hard linking or logic
                log.error(f"SEVERE ERROR! File {rel_path_to_delete} not found in new revision before deletion")
                raise storage.AccessError("File to delete was not found in the new revision")

            # Check whether the file is an artifact
            if analysis.is_artifact(path_in_new_revision):
                # If so, delete all associated metadata files in the new revision
                async for p in util.paths_recursive(path_in_new_revision.parent):
                    # Construct full path within the new revision
                    metadata_path_obj = creating.interim_path / p
                    if p.name.startswith(rel_path_to_delete.name + "."):
                        await aiofiles.os.remove(metadata_path_obj)
                        metadata_files_deleted += 1

            # Delete the file
            await aiofiles.os.remove(path_in_new_revision)
        return metadata_files_deleted

    async def import_from_svn(
        self, project_name: str, version_name: str, svn_url: str, revision: str, target_subdirectory: str | None
    ) -> sql.Task:
        task_args = {
            "svn_url": svn_url,
            "revision": revision,
            "target_subdirectory": target_subdirectory,
            "project_name": project_name,
            "version_name": version_name,
            "asf_uid": self.__asf_uid,
        }
        svn_import_task = sql.Task(
            task_type=sql.TaskType.SVN_IMPORT_FILES,
            task_args=task_args,
            asf_uid=util.unwrap(self.__asf_uid),
            added=datetime.datetime.now(datetime.UTC),
            status=sql.TaskStatus.QUEUED,
            project_name=project_name,
            version_name=version_name,
        )
        self.__data.add(svn_import_task)
        await self.__data.commit()
        await self.__data.refresh(svn_import_task)
        return svn_import_task

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
        self.__write_as.append_to_audit_log(
            action="release.start",
            project_name=project_name,
            version=version,
            created=release.created.isoformat(),
        )
        return release, project

    async def upload_file(self, args: api.ReleaseUploadArgs) -> sql.Revision:
        file_bytes = base64.b64decode(args.content, validate=True)
        file_path = args.relpath.lstrip("/")
        description = f"Upload via API: {file_path}"
        async with self.create_and_manage_revision(args.project, args.version, description) as creating:
            target_path = pathlib.Path(creating.interim_path) / file_path
            await aiofiles.os.makedirs(target_path.parent, exist_ok=True)
            if target_path.exists():
                raise storage.AccessError("File already exists")
            async with aiofiles.open(target_path, "wb") as f:
                await f.write(file_bytes)
        if creating.new is None:
            raise storage.AccessError("Failed to create revision")
        async with db.session() as data:
            release_name = sql.release_name(args.project, args.version)
            return await data.revision(
                release_name=release_name,
                number=creating.new.number,
            ).demand(storage.AccessError("Revision not found"))


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

    async def delete(
        self,
        project_name: str,
        version: str,
        phase: db.Opt[sql.ReleasePhase] = db.NOT_SET,
        include_downloads: bool = True,
    ) -> str | None:
        """Handle the deletion of database records and filesystem data for a release."""
        release = await self.__data.release(
            project_name=project_name, version=version, phase=phase, _project=True
        ).demand(storage.AccessError(f"Release '{project_name} {version}' not found."))
        release_dir = util.release_directory_base(release)

        # Delete from the database
        log.info(f"Deleting database records for release: {project_name} {version}")
        # Cascade should handle this, but we delete manually anyway
        tasks_to_delete = await self.__data.task(project_name=release.project.name, version_name=release.version).all()
        for task in tasks_to_delete:
            await self.__data.delete(task)
        log.debug(f"Deleted {len(tasks_to_delete)} tasks for {project_name} {version}")

        checks_to_delete = await self.__data.check_result(release_name=release.name).all()
        for check in checks_to_delete:
            await self.__data.delete(check)
        log.debug(f"Deleted {len(checks_to_delete)} check results for {project_name} {version}")

        # TODO: Ensure that revisions are not deleted
        # But this makes testing difficult
        # Perhaps delete revisions if associated with test accounts only
        # But we want to test actual mechanisms, not special case tests
        # We could create uniquely named releases in tests
        # Currently part of the discussion in #171, but should be its own issue
        await self.__data.delete(release)
        log.info(f"Deleted release record: {project_name} {version}")
        await self.__data.commit()

        if include_downloads:
            await self.__delete_release_data_downloads(release)
        warning = await self.__delete_release_data_filesystem(release_dir, project_name, version)
        self.__write_as.append_to_audit_log(
            action="release.delete",
            project_name=project_name,
            version=version,
            warning=warning,
        )
        return warning

    async def __delete_release_data_downloads(self, release: sql.Release) -> None:
        # Delete hard links from the downloads directory
        finished_dir = util.release_directory(release)
        if await aiofiles.os.path.isdir(finished_dir):
            release_inodes = set()
            async for file_path in util.paths_recursive(finished_dir):
                try:
                    stat_result = await aiofiles.os.stat(finished_dir / file_path)
                    release_inodes.add(stat_result.st_ino)
                except FileNotFoundError:
                    continue

            if release_inodes:
                downloads_dir = util.get_downloads_dir()
                async for link_path in util.paths_recursive(downloads_dir):
                    full_link_path = downloads_dir / link_path
                    try:
                        link_stat = await aiofiles.os.stat(full_link_path)
                        if link_stat.st_ino in release_inodes:
                            await aiofiles.os.remove(full_link_path)
                            log.info(f"Deleted hard link: {full_link_path}")
                    except FileNotFoundError:
                        continue

    async def __delete_release_data_filesystem(
        self, release_dir: pathlib.Path, project_name: str, version: str
    ) -> str | None:
        # Delete from the filesystem
        try:
            if await aiofiles.os.path.isdir(release_dir):
                log.info("Deleting filesystem directory: %s", release_dir)
                # Believe this to be another bug in mypy Protocol handling
                # TODO: Confirm that this is a bug, and report upstream
                await aioshutil.rmtree(release_dir)  # type: ignore[call-arg]
                log.info("Successfully deleted directory: %s", release_dir)
            else:
                log.warning("Filesystem directory not found, skipping deletion: %s", release_dir)
        except Exception as e:
            log.exception("Error deleting filesystem directory %s:", release_dir)
            return (
                f"Database records for '{project_name} {version}' deleted,"
                f" but failed to delete filesystem directory: {e!s}"
            )
        return None


class FoundationAdmin(CommitteeMember):
    def __init__(
        self, write: storage.Write, write_as: storage.WriteAsFoundationAdmin, data: db.Session, committee_name: str
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
