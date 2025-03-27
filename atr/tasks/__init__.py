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

import os.path

import aiofiles.os

import atr.db.models as models
import atr.tasks.archive as archive
import atr.tasks.hashing as hashing
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
                task_type="verify_signature",
                task_args=[
                    release.committee.name,
                    full_artifact_path,
                    full_signature_path,
                ],
                release_name=release.name,
                path=signature_path,
                modified=modified,
            ),
        )

    return tasks


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
            task_type="verify_file_hash",
            task_args=hashing.Check(
                original_file=original_file, hash_file=full_hash_file_path, algorithm=algorithm
            ).model_dump(),
            release_name=release.name,
            path=hash_file,
            modified=modified,
        ),
    )

    return tasks


async def tar_gz_checks(release: models.Release, path: str, signature_path: str | None = None) -> list[models.Task]:
    # TODO: We should probably use an enum for task_type
    full_path = str(util.get_release_candidate_draft_dir() / release.project.name / release.version / path)
    filename = os.path.basename(path)
    modified = int(await aiofiles.os.path.getmtime(full_path))

    tasks = [
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_archive_integrity",
            task_args=archive.CheckIntegrity(path=full_path).model_dump(),
            release_name=release.name,
            path=path,
            modified=modified,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_archive_structure",
            task_args=[full_path, filename],
            release_name=release.name,
            path=path,
            modified=modified,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_license_files",
            task_args=[full_path],
            release_name=release.name,
            path=path,
            modified=modified,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_license_headers",
            task_args=[full_path],
            release_name=release.name,
            path=path,
            modified=modified,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_rat_license",
            task_args=[full_path],
            release_name=release.name,
            path=path,
            modified=modified,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="generate_cyclonedx_sbom",
            task_args=[full_path],
            release_name=release.name,
            path=path,
            modified=modified,
        ),
    ]

    return tasks
