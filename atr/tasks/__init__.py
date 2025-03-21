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
import atr.util as util


async def artifact_checks(
    path: str, signature_path: str | None = None, committee_name: str | None = None
) -> list[models.Task]:
    # TODO: We should probably use an enum for task_type
    if path.startswith("releases/"):
        artifact_sha3 = path.split("/")[1]
    else:
        artifact_sha3 = await util.file_sha3(path)
    filename = os.path.basename(path)
    if signature_path is None:
        signature_path = path + ".asc"
        if not (await aiofiles.os.path.exists(signature_path)):
            signature_path = None

    tasks = [
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_archive_integrity",
            task_args=archive.CheckIntegrity(path=path).model_dump(),
            package_sha3=artifact_sha3,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_archive_structure",
            task_args=[path, filename],
            package_sha3=artifact_sha3,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_license_files",
            task_args=[path],
            package_sha3=artifact_sha3,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_license_headers",
            task_args=[path],
            package_sha3=artifact_sha3,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_rat_license",
            task_args=[path],
            package_sha3=artifact_sha3,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="generate_cyclonedx_sbom",
            task_args=[path],
            package_sha3=artifact_sha3,
        ),
    ]

    if signature_path and committee_name:
        tasks.append(
            models.Task(
                status=models.TaskStatus.QUEUED,
                task_type="verify_signature",
                task_args=[
                    committee_name,
                    path,
                    signature_path,
                ],
                package_sha3=artifact_sha3,
            ),
        )

    return tasks
