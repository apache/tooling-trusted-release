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
import base64
import contextlib
import datetime
import hashlib
import pathlib
from typing import TYPE_CHECKING, Final

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
    from collections.abc import AsyncGenerator, Sequence

    import werkzeug.datastructures as datastructures

SPECIAL_SUFFIXES: Final[frozenset[str]] = frozenset({".asc", ".sha256", ".sha512"})


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
            asf_uid=self.__asf_uid,
            project_name=project_name,
            version=version,
            warning=warning,
        )
        return warning

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

    async def generate_hash_file(
        self, project_name: str, version_name: str, rel_path: pathlib.Path, hash_type: str
    ) -> None:
        description = "Hash generation through web interface"
        async with self.create_and_manage_revision(project_name, version_name, description) as creating:
            # Uses new_revision_number for logging only
            path_in_new_revision = creating.interim_path / rel_path
            hash_path_rel = rel_path.name + f".{hash_type}"
            hash_path_in_new_revision = creating.interim_path / rel_path.parent / hash_path_rel

            # Check that the source file exists in the new revision
            if not await aiofiles.os.path.exists(path_in_new_revision):
                log.error(f"Source file {rel_path} not found in new revision for hash generation.")
                raise storage.AccessError("Source file not found in the new revision.")

            # Check that the hash file does not already exist in the new revision
            if await aiofiles.os.path.exists(hash_path_in_new_revision):
                raise storage.AccessError(f"{hash_type} file already exists")

            # Read the source file from the new revision and compute the hash
            hash_obj = hashlib.sha256() if hash_type == "sha256" else hashlib.sha512()
            async with aiofiles.open(path_in_new_revision, "rb") as f:
                while chunk := await f.read(8192):
                    hash_obj.update(chunk)

            # Write the hash file into the new revision
            hash_value = hash_obj.hexdigest()
            async with aiofiles.open(hash_path_in_new_revision, "w") as f:
                await f.write(f"{hash_value}  {rel_path.name}\n")

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

    async def move_file(
        self, project_name: str, version_name: str, source_files_rel: list[pathlib.Path], target_dir_rel: pathlib.Path
    ) -> tuple[str | None, list[str], list[str]]:
        description = "File move through web interface"
        moved_files_names: list[str] = []
        skipped_files_names: list[str] = []

        async with self.create_and_manage_revision(project_name, version_name, description) as creating:
            await self.__setup_revision(
                source_files_rel,
                target_dir_rel,
                creating,
                moved_files_names,
                skipped_files_names,
            )
        creation_error = str(creating.failed) if (creating.failed is not None) else None
        return creation_error, moved_files_names, skipped_files_names

    async def remove_rc_tags(self, project_name: str, version_name: str) -> tuple[str | None, int, list[str]]:
        description = "Remove RC tags from paths via web interface"
        error_messages: list[str] = []

        async with self.create_and_manage_revision(project_name, version_name, description) as creating:
            renamed_count = await self.__remove_rc_tags_revision(creating, error_messages)
        creation_error = str(creating.failed) if (creating.failed is not None) else None
        return creation_error, renamed_count, error_messages

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
            asf_uid=self.__asf_uid,
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

    async def upload_files(
        self,
        project_name: str,
        version_name: str,
        file_name: pathlib.Path | None,
        files: Sequence[datastructures.FileStorage],
    ) -> int:
        """Process and save the uploaded files into a new draft revision."""
        number_of_files = len(files)
        description = f"Upload of {number_of_files} file{'' if number_of_files == 1 else 's'} through web interface"
        async with self.create_and_manage_revision(project_name, version_name, description) as creating:
            # Save each uploaded file to the new revision directory
            for file in files:
                # Determine the target path within the new revision directory
                relative_file_path: pathlib.Path
                if not file_name:
                    if not file.filename:
                        raise storage.AccessError("No filename provided")
                    # Use the original name
                    relative_file_path = pathlib.Path(file.filename)
                else:
                    # Use the provided name, relative to its anchor
                    # In other words, ignore the leading "/"
                    relative_file_path = file_name.relative_to(file_name.anchor)

                # Construct path inside the new revision directory
                target_path = creating.interim_path / relative_file_path
                # Ensure parent directories exist within the new revision
                await aiofiles.os.makedirs(target_path.parent, exist_ok=True)
                await self.__save_file(file, target_path)
        return len(files)

    async def __current_paths(self, creating: revision.Creating) -> list[pathlib.Path]:
        all_current_paths_interim: list[pathlib.Path] = []
        async for p_rel_interim in util.paths_recursive_all(creating.interim_path):
            all_current_paths_interim.append(p_rel_interim)

        # This manner of sorting is necessary to ensure that directories are removed after their contents
        all_current_paths_interim.sort(key=lambda p: (-len(p.parts), str(p)))
        return all_current_paths_interim

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

    def __related_files(self, path: pathlib.Path) -> list[pathlib.Path]:
        base_path = path.with_suffix("") if (path.suffix in SPECIAL_SUFFIXES) else path
        parent_dir = base_path.parent
        name_without_ext = base_path.name
        return [
            parent_dir / name_without_ext,
            parent_dir / f"{name_without_ext}.asc",
            parent_dir / f"{name_without_ext}.sha256",
            parent_dir / f"{name_without_ext}.sha512",
        ]

    async def __remove_rc_tags_revision(
        self,
        creating: revision.Creating,
        error_messages: list[str],
    ) -> int:
        all_current_paths_interim = await self.__current_paths(creating)
        renamed_count_local = 0
        for path_rel_original_interim in all_current_paths_interim:
            path_rel_stripped_interim = analysis.candidate_removed(path_rel_original_interim)

            if path_rel_original_interim != path_rel_stripped_interim:
                # Absolute paths of the source and destination
                full_original_path = creating.interim_path / path_rel_original_interim
                full_stripped_path = creating.interim_path / path_rel_stripped_interim

                skip, renamed_count_local = await self.__remove_rc_tags_revision_item(
                    path_rel_original_interim,
                    full_original_path,
                    full_stripped_path,
                    error_messages,
                    renamed_count_local,
                )
                if skip:
                    continue

                try:
                    if not await aiofiles.os.path.exists(full_stripped_path.parent):
                        # This could happen if e.g. a file is in an RC tagged directory
                        await aiofiles.os.makedirs(full_stripped_path.parent, exist_ok=True)

                    if await aiofiles.os.path.exists(full_stripped_path):
                        error_messages.append(
                            f"Skipped '{path_rel_original_interim}':"
                            f" target '{path_rel_stripped_interim}' already exists."
                        )
                        continue

                    await aiofiles.os.rename(full_original_path, full_stripped_path)
                    renamed_count_local += 1
                except Exception as e:
                    error_messages.append(f"Error renaming '{path_rel_original_interim}': {e}")
        return renamed_count_local

    async def __remove_rc_tags_revision_item(
        self,
        path_rel_original_interim: pathlib.Path,
        full_original_path: pathlib.Path,
        full_stripped_path: pathlib.Path,
        error_messages: list[str],
        renamed_count_local: int,
    ) -> tuple[bool, int]:
        if await aiofiles.os.path.isdir(full_original_path):
            # If moving an RC tagged directory to an existing directory...
            is_target_dir_and_exists = await aiofiles.os.path.isdir(full_stripped_path)
            if is_target_dir_and_exists and (full_stripped_path != full_original_path):
                try:
                    # And the source directory is empty...
                    if not await aiofiles.os.listdir(full_original_path):
                        # This means we probably moved files out of the RC tagged directory
                        # In any case, we can't move it, so we have to delete it
                        await aiofiles.os.rmdir(full_original_path)
                        renamed_count_local += 1
                    else:
                        error_messages.append(
                            f"Source RC directory '{path_rel_original_interim}' is not empty, skipping."
                        )
                except OSError as e:
                    error_messages.append(f"Error removing source RC directory '{path_rel_original_interim}': {e}")
                return True, renamed_count_local
        return False, renamed_count_local

    async def __save_file(self, file: datastructures.FileStorage, target_path: pathlib.Path) -> None:
        async with aiofiles.open(target_path, "wb") as f:
            while chunk := await asyncio.to_thread(file.stream.read, 8192):
                await f.write(chunk)

    async def __setup_revision(
        self,
        source_files_rel: list[pathlib.Path],
        target_dir_rel: pathlib.Path,
        creating: revision.Creating,
        moved_files_names: list[str],
        skipped_files_names: list[str],
    ) -> None:
        target_path = creating.interim_path / target_dir_rel
        try:
            target_path.resolve().relative_to(creating.interim_path.resolve())
        except ValueError:
            # Path traversal detected
            raise revision.FailedError("Paths must be restricted to the release directory")

        if not await aiofiles.os.path.exists(target_path):
            for part in target_path.parts:
                # TODO: This .prefix check could include some existing directory segment
                if part.startswith("."):
                    raise revision.FailedError("Segments must not start with '.'")
                if ".." in part:
                    raise revision.FailedError("Segments must not contain '..'")

            try:
                await aiofiles.os.makedirs(target_path)
            except OSError:
                raise revision.FailedError("Failed to create target directory")
        elif not await aiofiles.os.path.isdir(target_path):
            raise revision.FailedError("Target path is not a directory")

        for source_file_rel in source_files_rel:
            await self.__setup_revision_item(
                source_file_rel, target_dir_rel, creating, moved_files_names, skipped_files_names, target_path
            )

    async def __setup_revision_item(
        self,
        source_file_rel: pathlib.Path,
        target_dir_rel: pathlib.Path,
        creating: revision.Creating,
        moved_files_names: list[str],
        skipped_files_names: list[str],
        target_path: pathlib.Path,
    ) -> None:
        if source_file_rel.parent == target_dir_rel:
            skipped_files_names.append(source_file_rel.name)
            return

        full_source_item_path = creating.interim_path / source_file_rel

        if await aiofiles.os.path.isdir(full_source_item_path):
            if (target_dir_rel == source_file_rel) or (creating.interim_path / target_dir_rel).resolve().is_relative_to(
                full_source_item_path.resolve()
            ):
                raise revision.FailedError("Cannot move a directory into itself or a subdirectory of itself")

            final_target_for_item = target_path / source_file_rel.name
            if await aiofiles.os.path.exists(final_target_for_item):
                raise revision.FailedError("Target name already exists")

            await aiofiles.os.rename(full_source_item_path, final_target_for_item)
            moved_files_names.append(source_file_rel.name)
        else:
            related_files = self.__related_files(source_file_rel)
            bundle = [f for f in related_files if await aiofiles.os.path.exists(creating.interim_path / f)]
            for f_check in bundle:
                if await aiofiles.os.path.isdir(creating.interim_path / f_check):
                    raise revision.FailedError("A related 'file' is actually a directory")

            collisions = [f.name for f in bundle if await aiofiles.os.path.exists(target_path / f.name)]
            if collisions:
                raise revision.FailedError("A related file already exists in the target directory")

            for f in bundle:
                await aiofiles.os.rename(creating.interim_path / f, target_path / f.name)
                if f == source_file_rel:
                    moved_files_names.append(f.name)


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
