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

from collections.abc import Awaitable, Callable, Coroutine
from typing import Any, Final

import atr.db as db
import atr.models.results as results
import atr.models.sql as sql
import atr.tasks.checks.hashing as hashing
import atr.tasks.checks.license as license
import atr.tasks.checks.paths as paths
import atr.tasks.checks.rat as rat
import atr.tasks.checks.signature as signature
import atr.tasks.checks.targz as targz
import atr.tasks.checks.zipformat as zipformat
import atr.tasks.keys as keys
import atr.tasks.message as message
import atr.tasks.sbom as sbom
import atr.tasks.svn as svn
import atr.tasks.vote as vote
import atr.util as util


async def asc_checks(asf_uid: str, release: sql.Release, revision: str, signature_path: str) -> list[sql.Task]:
    """Create signature check task for a .asc file."""
    tasks = []

    if release.committee:
        tasks.append(
            queued(
                asf_uid,
                sql.TaskType.SIGNATURE_CHECK,
                release,
                revision,
                signature_path,
                {"committee_name": release.committee.name},
            )
        )

    return tasks


async def draft_checks(
    asf_uid: str, project_name: str, release_version: str, revision_number: str, caller_data: db.Session | None = None
) -> int:
    """Core logic to analyse a draft revision and queue checks."""
    # Construct path to the specific revision
    # We don't have the release object here, so we can't use util.release_directory
    revision_path = util.get_unfinished_dir() / project_name / release_version / revision_number
    relative_paths = [path async for path in util.paths_recursive(revision_path)]

    async with db.ensure_session(caller_data) as data:
        release = await data.release(name=sql.release_name(project_name, release_version), _committee=True).demand(
            RuntimeError("Release not found")
        )
        for path in relative_paths:
            path_str = str(path)
            task_function: Callable[[str, sql.Release, str, str], Awaitable[list[sql.Task]]] | None = None
            for suffix, func in TASK_FUNCTIONS.items():
                if path.name.endswith(suffix):
                    task_function = func
                    break
            if task_function:
                for task in await task_function(asf_uid, release, revision_number, path_str):
                    task.revision_number = revision_number
                    data.add(task)
            # TODO: Should we check .json files for their content?
            # Ideally we would not have to do that
            if path.name.endswith(".cdx.json"):
                data.add(
                    queued(
                        asf_uid,
                        sql.TaskType.SBOM_TOOL_SCORE,
                        release,
                        revision_number,
                        path_str,
                        extra_args={
                            "project_name": project_name,
                            "version_name": release_version,
                            "revision_number": revision_number,
                            "file_path": path_str,
                            "asf_uid": asf_uid,
                        },
                    )
                )

        is_podling = False
        if release.project.committee is not None:
            if release.project.committee.is_podling:
                is_podling = True
        path_check_task = queued(
            asf_uid, sql.TaskType.PATHS_CHECK, release, revision_number, extra_args={"is_podling": is_podling}
        )
        data.add(path_check_task)
        if caller_data is None:
            await data.commit()

    return len(relative_paths)


async def keys_import_file(
    asf_uid: str, project_name: str, version_name: str, revision_number: str, caller_data: db.Session | None = None
) -> None:
    """Import a KEYS file from a draft release candidate revision."""
    async with db.ensure_session(caller_data) as data:
        data.add(
            sql.Task(
                status=sql.TaskStatus.QUEUED,
                task_type=sql.TaskType.KEYS_IMPORT_FILE,
                task_args=keys.ImportFile(
                    asf_uid=asf_uid,
                    project_name=project_name,
                    version_name=version_name,
                ).model_dump(),
                asf_uid=asf_uid,
                revision_number=revision_number,
                primary_rel_path=None,
            )
        )
        await data.commit()


def queued(
    asf_uid: str,
    task_type: sql.TaskType,
    release: sql.Release,
    revision_number: str,
    primary_rel_path: str | None = None,
    extra_args: dict[str, Any] | None = None,
) -> sql.Task:
    return sql.Task(
        status=sql.TaskStatus.QUEUED,
        task_type=task_type,
        task_args=extra_args or {},
        asf_uid=asf_uid,
        project_name=release.project.name,
        version_name=release.version,
        revision_number=revision_number,
        primary_rel_path=primary_rel_path,
    )


def resolve(task_type: sql.TaskType) -> Callable[..., Awaitable[results.Results | None]]:  # noqa: C901
    match task_type:
        case sql.TaskType.HASHING_CHECK:
            return hashing.check
        case sql.TaskType.KEYS_IMPORT_FILE:
            return keys.import_file
        case sql.TaskType.LICENSE_FILES:
            return license.files
        case sql.TaskType.LICENSE_HEADERS:
            return license.headers
        case sql.TaskType.MESSAGE_SEND:
            return message.send
        case sql.TaskType.PATHS_CHECK:
            return paths.check
        case sql.TaskType.RAT_CHECK:
            return rat.check
        case sql.TaskType.SBOM_AUGMENT:
            return sbom.augment
        case sql.TaskType.SBOM_GENERATE_CYCLONEDX:
            return sbom.generate_cyclonedx
        case sql.TaskType.SBOM_QS_SCORE:
            return sbom.score_qs
        case sql.TaskType.SBOM_TOOL_SCORE:
            return sbom.score_tool
        case sql.TaskType.SIGNATURE_CHECK:
            return signature.check
        case sql.TaskType.SVN_IMPORT_FILES:
            return svn.import_files
        case sql.TaskType.TARGZ_INTEGRITY:
            return targz.integrity
        case sql.TaskType.TARGZ_STRUCTURE:
            return targz.structure
        case sql.TaskType.VOTE_INITIATE:
            return vote.initiate
        case sql.TaskType.ZIPFORMAT_INTEGRITY:
            return zipformat.integrity
        case sql.TaskType.ZIPFORMAT_STRUCTURE:
            return zipformat.structure
        # NOTE: Do NOT add "case _" here
        # Otherwise we lose exhaustiveness checking


async def sha_checks(asf_uid: str, release: sql.Release, revision: str, hash_file: str) -> list[sql.Task]:
    """Create hash check task for a .sha256 or .sha512 file."""
    tasks = []

    tasks.append(queued(asf_uid, sql.TaskType.HASHING_CHECK, release, revision, hash_file))

    return tasks


async def tar_gz_checks(asf_uid: str, release: sql.Release, revision: str, path: str) -> list[sql.Task]:
    """Create check tasks for a .tar.gz or .tgz file."""
    # This release has committee, as guaranteed in draft_checks
    is_podling = (release.project.committee is not None) and release.project.committee.is_podling
    tasks = [
        queued(asf_uid, sql.TaskType.LICENSE_FILES, release, revision, path, extra_args={"is_podling": is_podling}),
        queued(asf_uid, sql.TaskType.LICENSE_HEADERS, release, revision, path),
        queued(asf_uid, sql.TaskType.RAT_CHECK, release, revision, path),
        queued(asf_uid, sql.TaskType.TARGZ_INTEGRITY, release, revision, path),
        queued(asf_uid, sql.TaskType.TARGZ_STRUCTURE, release, revision, path),
    ]

    return tasks


async def zip_checks(asf_uid: str, release: sql.Release, revision: str, path: str) -> list[sql.Task]:
    """Create check tasks for a .zip file."""
    # This release has committee, as guaranteed in draft_checks
    is_podling = (release.project.committee is not None) and release.project.committee.is_podling
    tasks = [
        queued(asf_uid, sql.TaskType.LICENSE_FILES, release, revision, path, extra_args={"is_podling": is_podling}),
        queued(asf_uid, sql.TaskType.LICENSE_HEADERS, release, revision, path),
        queued(asf_uid, sql.TaskType.RAT_CHECK, release, revision, path),
        queued(asf_uid, sql.TaskType.ZIPFORMAT_INTEGRITY, release, revision, path),
        queued(asf_uid, sql.TaskType.ZIPFORMAT_STRUCTURE, release, revision, path),
    ]
    return tasks


TASK_FUNCTIONS: Final[dict[str, Callable[..., Coroutine[Any, Any, list[sql.Task]]]]] = {
    ".asc": asc_checks,
    ".sha256": sha_checks,
    ".sha512": sha_checks,
    ".tar.gz": tar_gz_checks,
    ".tgz": tar_gz_checks,
    ".zip": zip_checks,
}
