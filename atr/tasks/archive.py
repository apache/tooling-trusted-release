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

import logging
import os.path
import tarfile
from typing import Any, Final

from pydantic import BaseModel, Field

import atr.tasks.task as task

_LOGGER = logging.getLogger(__name__)


class CheckIntegrity(BaseModel):
    """Parameters for archive integrity checking."""

    path: str = Field(..., description="Path to the .tar.gz file to check")
    chunk_size: int = Field(default=4096, description="Size of chunks to read when checking the file")


def check_integrity(args: dict[str, Any]) -> tuple[task.Status, str | None, tuple[Any, ...]]:
    """Check the integrity of a .tar.gz file."""
    # TODO: We should standardise the "ERROR" mechanism here in the data
    # Then we can have a single task wrapper for all tasks
    # TODO: We should use task.TaskError as standard, and maybe typeguard each function
    data = CheckIntegrity(**args)
    task_results = task.results_as_tuple(_check_integrity_core(data.path, data.chunk_size))
    _LOGGER.info(f"Verified {data.path} and computed size {task_results[0]}")
    return task.COMPLETED, None, task_results


def check_structure(args: list[str]) -> tuple[task.Status, str | None, tuple[Any, ...]]:
    """Check the structure of a .tar.gz file."""
    task_results = task.results_as_tuple(_check_structure_core(*args))
    _LOGGER.info(f"Verified archive structure for {args}")
    status = task.FAILED if not task_results[0]["valid"] else task.COMPLETED
    error = task_results[0]["message"] if not task_results[0]["valid"] else None
    return status, error, task_results


def root_directory(tgz_path: str) -> str:
    """Find the root directory in a tar archive and validate that it has only one root dir."""
    root = None

    with tarfile.open(tgz_path, mode="r|gz") as tf:
        for member in tf:
            parts = member.name.split("/", 1)
            if len(parts) >= 1:
                if not root:
                    root = parts[0]
                elif parts[0] != root:
                    raise task.Error(f"Multiple root directories found: {root}, {parts[0]}")

    if not root:
        raise task.Error("No root directory found in archive")

    return root


def _check_integrity_core(tgz_path: str, chunk_size: int = 4096) -> int:
    """Verify a .tar.gz file and compute its uncompressed size."""
    total_size = 0

    with tarfile.open(tgz_path, mode="r|gz") as tf:
        for member in tf:
            total_size += member.size
            # Verify file by extraction
            if member.isfile():
                f = tf.extractfile(member)
                if f is not None:
                    while True:
                        data = f.read(chunk_size)
                        if not data:
                            break
    return total_size


def _check_structure_core(tgz_path: str, filename: str) -> dict[str, Any]:
    """
    Verify that the archive contains exactly one root directory named after the package.
    The package name should match the archive filename without the .tar.gz extension.
    """
    expected_root: Final[str] = os.path.splitext(os.path.splitext(filename)[0])[0]

    try:
        root = root_directory(tgz_path)
    except ValueError as e:
        return {"valid": False, "root_dirs": [], "message": str(e)}

    if root != expected_root:
        return {
            "valid": False,
            "root_dirs": [root],
            "message": f"Root directory '{root}' does not match expected name '{expected_root}'",
        }

    return {"valid": True, "root_dirs": [root], "message": "Archive structure is valid"}
