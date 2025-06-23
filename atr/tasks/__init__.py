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

import contextlib
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any, Final

import atr.db as db
import atr.db.models as models
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


async def asc_checks(release: models.Release, revision: str, signature_path: str) -> list[models.Task]:
    """Create signature check task for a .asc file."""
    tasks = []

    if release.committee:
        tasks.append(
            queued(
                models.TaskType.SIGNATURE_CHECK,
                release,
                revision,
                signature_path,
                {"committee_name": release.committee.name},
            )
        )

    return tasks


async def draft_checks(
    project_name: str, release_version: str, revision_number: str, caller_data: db.Session | None = None
) -> int:
    """Core logic to analyse a draft revision and queue checks."""
    # Construct path to the specific revision
    # We don't have the release object here, so we can't use util.release_directory
    revision_path = util.get_unfinished_dir() / project_name / release_version / revision_number
    relative_paths = [path async for path in util.paths_recursive(revision_path)]

    async with ensure_session(caller_data) as data:
        release = await data.release(name=models.release_name(project_name, release_version), _committee=True).demand(
            RuntimeError("Release not found")
        )
        for path in relative_paths:
            path_str = str(path)
            task_function: Callable[[models.Release, str, str], Awaitable[list[models.Task]]] | None = None
            for suffix, func in TASK_FUNCTIONS.items():
                if path.name.endswith(suffix):
                    task_function = func
                    break
            if task_function:
                for task in await task_function(release, revision_number, path_str):
                    task.revision_number = revision_number
                    data.add(task)

        path_check_task = queued(models.TaskType.PATHS_CHECK, release, revision_number)
        data.add(path_check_task)
        if caller_data is None:
            await data.commit()

    return len(relative_paths)


def ensure_session(caller_data: db.Session | None) -> db.Session | contextlib.nullcontext[db.Session]:
    # TODO: Move to interaction.py
    # This pattern is also used in routes/keys.py
    if caller_data is None:
        return db.session()
    return contextlib.nullcontext(caller_data)


async def keys_import_file(
    release_name: str, revision_number: str, abs_keys_path: str, caller_data: db.Session | None = None
) -> None:
    """Import a KEYS file from a draft release candidate revision."""
    async with ensure_session(caller_data) as data:
        data.add(
            models.Task(
                status=models.TaskStatus.QUEUED,
                task_type=models.TaskType.KEYS_IMPORT_FILE,
                task_args=keys.ImportFile(
                    release_name=release_name,
                    abs_keys_path=abs_keys_path,
                ).model_dump(),
                revision_number=revision_number,
                primary_rel_path=None,
            )
        )
        await data.commit()


def queued(
    task_type: models.TaskType,
    release: models.Release,
    revision_number: str,
    primary_rel_path: str | None = None,
    extra_args: dict[str, Any] | None = None,
) -> models.Task:
    return models.Task(
        status=models.TaskStatus.QUEUED,
        task_type=task_type,
        task_args=extra_args or {},
        project_name=release.project.name,
        version_name=release.version,
        revision_number=revision_number,
        primary_rel_path=primary_rel_path,
    )


def resolve(task_type: models.TaskType) -> Callable[..., Awaitable[str | None]]:  # noqa: C901
    match task_type:
        case models.TaskType.HASHING_CHECK:
            return hashing.check
        case models.TaskType.KEYS_IMPORT_FILE:
            return keys.import_file
        case models.TaskType.LICENSE_FILES:
            return license.files
        case models.TaskType.LICENSE_HEADERS:
            return license.headers
        case models.TaskType.MESSAGE_SEND:
            return message.send
        case models.TaskType.PATHS_CHECK:
            return paths.check
        case models.TaskType.RAT_CHECK:
            return rat.check
        case models.TaskType.SBOM_GENERATE_CYCLONEDX:
            return sbom.generate_cyclonedx
        case models.TaskType.SIGNATURE_CHECK:
            return signature.check
        case models.TaskType.SVN_IMPORT_FILES:
            return svn.import_files
        case models.TaskType.TARGZ_INTEGRITY:
            return targz.integrity
        case models.TaskType.TARGZ_STRUCTURE:
            return targz.structure
        case models.TaskType.VOTE_INITIATE:
            return vote.initiate
        case models.TaskType.ZIPFORMAT_INTEGRITY:
            return zipformat.integrity
        case models.TaskType.ZIPFORMAT_STRUCTURE:
            return zipformat.structure
        # NOTE: Do NOT add "case _" here
        # Otherwise we lose exhaustiveness checking


async def sha_checks(release: models.Release, revision: str, hash_file: str) -> list[models.Task]:
    """Create hash check task for a .sha256 or .sha512 file."""
    tasks = []

    tasks.append(queued(models.TaskType.HASHING_CHECK, release, revision, hash_file))

    return tasks


async def tar_gz_checks(release: models.Release, revision: str, path: str) -> list[models.Task]:
    """Create check tasks for a .tar.gz or .tgz file."""
    tasks = [
        queued(models.TaskType.LICENSE_FILES, release, revision, path),
        queued(models.TaskType.LICENSE_HEADERS, release, revision, path),
        queued(models.TaskType.RAT_CHECK, release, revision, path),
        queued(models.TaskType.TARGZ_INTEGRITY, release, revision, path),
        queued(models.TaskType.TARGZ_STRUCTURE, release, revision, path),
    ]

    return tasks


async def zip_checks(release: models.Release, revision: str, path: str) -> list[models.Task]:
    """Create check tasks for a .zip file."""
    tasks = [
        queued(models.TaskType.LICENSE_FILES, release, revision, path),
        queued(models.TaskType.LICENSE_HEADERS, release, revision, path),
        # queued(models.TaskType.RAT_CHECK, release, revision, path),
        queued(models.TaskType.ZIPFORMAT_INTEGRITY, release, revision, path),
        queued(models.TaskType.ZIPFORMAT_STRUCTURE, release, revision, path),
    ]
    return tasks


TASK_FUNCTIONS: Final[dict[str, Callable[..., Coroutine[Any, Any, list[models.Task]]]]] = {
    ".asc": asc_checks,
    ".sha256": sha_checks,
    ".sha512": sha_checks,
    ".tar.gz": tar_gz_checks,
    ".tgz": tar_gz_checks,
    ".zip": zip_checks,
}
