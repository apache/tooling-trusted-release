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

import hashlib
import logging
import secrets
from typing import Any, Final

import aiofiles
import pydantic

import atr.db.models as models
import atr.tasks.task as task

_LOGGER: Final = logging.getLogger(__name__)


class Check(pydantic.BaseModel):
    """Parameters for file hash checking."""

    original_file: str = pydantic.Field(..., description="Path to the original file")
    hash_file: str = pydantic.Field(..., description="Path to the hash file")
    algorithm: str = pydantic.Field(..., description="Hash algorithm to use")


async def check(args: dict[str, Any]) -> tuple[models.TaskStatus, str | None, tuple[Any, ...]]:
    """Check the hash of a file."""
    data = Check(**args)
    task_results = task.results_as_tuple(await _check_core(data.original_file, data.hash_file, data.algorithm))
    _LOGGER.info(f"Verified {data.original_file} and computed size {task_results[0]}")
    return task.COMPLETED, None, task_results


async def _check_core(
    original_file: str, hash_file: str, algorithm: str
) -> tuple[models.TaskStatus, str | None, tuple[Any, ...]]:
    """Check the hash of a file."""
    if algorithm == "sha256":
        hash_func = hashlib.sha256
    elif algorithm == "sha512":
        hash_func = hashlib.sha512
    else:
        raise task.Error(f"Unsupported hash algorithm: {algorithm}")
    h = hash_func()
    async with aiofiles.open(original_file, mode="rb") as f:
        while True:
            chunk = await f.read(4096)
            if not chunk:
                break
            h.update(chunk)
    computed_hash = h.hexdigest()
    async with aiofiles.open(hash_file) as f:
        expected_hash = await f.read()
    # May be in the format "HASH FILENAME\n"
    expected_hash = expected_hash.strip().split()[0]
    if secrets.compare_digest(computed_hash, expected_hash):
        return task.COMPLETED, None, ({"computed_hash": computed_hash, "expected_hash": expected_hash},)
    else:
        return (
            task.FAILED,
            f"Hash mismatch for {original_file}",
            ({"computed_hash": computed_hash, "expected_hash": expected_hash},),
        )
