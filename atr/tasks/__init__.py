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

from collections.abc import Awaitable, Callable

import aiofiles.os

import atr.db.models as models
import atr.tasks.checks.archive as archive
import atr.tasks.checks.hashing as hashing
import atr.tasks.checks.license as license
import atr.tasks.checks.paths as paths
import atr.tasks.checks.rat as rat
import atr.tasks.checks.signature as signature
import atr.tasks.rsync as rsync
import atr.tasks.sbom as sbom
import atr.tasks.vote as vote
import atr.util as util


async def asc_checks(release: models.Release, signature_path: str) -> list[models.Task]:
    tasks = []

    draft_dir = util.get_release_candidate_draft_dir() / release.project.name / release.version
    full_signature_path = str(draft_dir / signature_path)
    modified = int(await aiofiles.os.path.getmtime(full_signature_path))

    artifact_path = signature_path.removesuffix(".asc")
    full_artifact_path = str(draft_dir / artifact_path)
    if not (await aiofiles.os.path.exists(full_artifact_path)):
        raise RuntimeError(f"Artifact {full_artifact_path} does not exist")

    if release.committee:
        tasks.append(
            models.Task(
                status=models.TaskStatus.QUEUED,
                task_type=models.TaskType.SIGNATURE_CHECK,
                task_args=signature.Check(
                    release_name=release.name,
                    committee_name=release.committee.name,
                    abs_artifact_path=full_artifact_path,
                    abs_signature_path=full_signature_path,
                ).model_dump(),
                release_name=release.name,
                path=signature_path,
                modified=modified,
            ),
        )

    return tasks


def resolve(task_type: models.TaskType) -> Callable[..., Awaitable[str | None]]:  # noqa: C901
    match task_type:
        case models.TaskType.ARCHIVE_INTEGRITY:
            return archive.integrity
        case models.TaskType.ARCHIVE_STRUCTURE:
            return archive.structure
        case models.TaskType.HASHING_CHECK:
            return hashing.check
        case models.TaskType.LICENSE_FILES:
            return license.files
        case models.TaskType.LICENSE_HEADERS:
            return license.headers
        case models.TaskType.PATHS_CHECK:
            return paths.check
        case models.TaskType.RAT_CHECK:
            return rat.check
        case models.TaskType.RSYNC_ANALYSE:
            return rsync.analyse
        case models.TaskType.SIGNATURE_CHECK:
            return signature.check
        case models.TaskType.VOTE_INITIATE:
            return vote.initiate
        case models.TaskType.SBOM_GENERATE_CYCLONEDX:
            return sbom.generate_cyclonedx
        # NOTE: Do NOT add "case _" here
        # Otherwise we lose exhaustiveness checking


async def sha_checks(release: models.Release, hash_file: str) -> list[models.Task]:
    tasks = []

    full_hash_file_path = str(
        util.get_release_candidate_draft_dir() / release.project.name / release.version / hash_file
    )
    modified = int(await aiofiles.os.path.getmtime(full_hash_file_path))
    algorithm = "sha512"
    if hash_file.endswith(".sha512"):
        original_file = full_hash_file_path.removesuffix(".sha512")
    elif hash_file.endswith(".sha256"):
        original_file = full_hash_file_path.removesuffix(".sha256")
        algorithm = "sha256"
    else:
        raise RuntimeError(f"Unsupported hash file: {hash_file}")

    tasks.append(
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type=models.TaskType.HASHING_CHECK,
            task_args=hashing.Check(
                release_name=release.name,
                abs_path=original_file,
                abs_hash_file=full_hash_file_path,
                algorithm=algorithm,
            ).model_dump(),
            release_name=release.name,
            path=hash_file,
            modified=modified,
        ),
    )

    return tasks


async def tar_gz_checks(release: models.Release, path: str) -> list[models.Task]:
    # TODO: We should probably use an enum for task_type
    full_path = str(util.get_release_candidate_draft_dir() / release.project.name / release.version / path)
    # filename = os.path.basename(path)
    modified = int(await aiofiles.os.path.getmtime(full_path))

    tasks = [
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type=models.TaskType.ARCHIVE_INTEGRITY,
            task_args=archive.Integrity(release_name=release.name, abs_path=full_path).model_dump(),
            release_name=release.name,
            path=path,
            modified=modified,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type=models.TaskType.ARCHIVE_STRUCTURE,
            task_args=archive.Structure(release_name=release.name, abs_path=full_path).model_dump(),
            release_name=release.name,
            path=path,
            modified=modified,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type=models.TaskType.LICENSE_FILES,
            task_args=license.Files(release_name=release.name, abs_path=full_path).model_dump(),
            release_name=release.name,
            path=path,
            modified=modified,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type=models.TaskType.LICENSE_HEADERS,
            task_args=license.Headers(release_name=release.name, abs_path=full_path).model_dump(),
            release_name=release.name,
            path=path,
            modified=modified,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type=models.TaskType.RAT_CHECK,
            task_args=rat.Check(release_name=release.name, abs_path=full_path).model_dump(),
            release_name=release.name,
            path=path,
            modified=modified,
        ),
    ]

    return tasks
