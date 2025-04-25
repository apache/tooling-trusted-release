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

import asyncio
import logging
import tarfile
from typing import Final

import atr.tasks.checks as checks

_LOGGER: Final = logging.getLogger(__name__)


async def integrity(args: checks.FunctionArguments) -> str | None:
    """Check the integrity of a .tar.gz file."""
    recorder = await args.recorder()
    if not (artifact_abs_path := await recorder.abs_path()):
        return None

    _LOGGER.info(f"Checking integrity for {artifact_abs_path} (rel: {args.primary_rel_path})")

    chunk_size = 4096
    try:
        size = await asyncio.to_thread(_integrity_core, str(artifact_abs_path), chunk_size)
        await recorder.success("Able to read all entries of the archive using tarfile", {"size": size})
    except Exception as e:
        await recorder.failure("Unable to read all entries of the archive using tarfile", {"error": str(e)})
    return None


def root_directory(tgz_path: str) -> str:
    """Find the root directory in a tar archive and validate that it has only one root dir."""
    root = None

    with tarfile.open(tgz_path, mode="r|gz") as tf:
        for member in tf:
            if member.name and member.name.split("/")[-1].startswith("._"):
                # Metadata convention
                continue

            parts = member.name.split("/", 1)
            if len(parts) >= 1:
                if not root:
                    root = parts[0]
                elif parts[0] != root:
                    raise ValueError(f"Multiple root directories found: {root}, {parts[0]}")

    if not root:
        raise ValueError("No root directory found in archive")

    return root


async def structure(args: checks.FunctionArguments) -> str | None:
    """Check the structure of a .tar.gz file."""
    recorder = await args.recorder()
    if not (artifact_abs_path := await recorder.abs_path()):
        return None

    filename = artifact_abs_path.name
    expected_root: Final[str] = (
        filename.removesuffix(".tar.gz") if filename.endswith(".tar.gz") else filename.removesuffix(".tgz")
    )
    _LOGGER.info(
        f"Checking structure for {artifact_abs_path} (expected root: {expected_root}) (rel: {args.primary_rel_path})"
    )

    try:
        root = await asyncio.to_thread(root_directory, str(artifact_abs_path))
        if root == expected_root:
            await recorder.success(
                "Archive contains exactly one root directory matching the expected name",
                {"root": root, "expected": expected_root},
            )
        else:
            await recorder.warning(
                f"Root directory '{root}' does not match expected name '{expected_root}'",
                {"root": root, "expected": expected_root},
            )
    except Exception as e:
        await recorder.failure("Unable to verify archive structure", {"error": str(e)})
    return None


def _integrity_core(tgz_path: str, chunk_size: int = 4096) -> int:
    """Verify a .tar.gz file and compute its uncompressed size."""
    total_size = 0

    with tarfile.open(tgz_path, mode="r|gz") as tf:
        for member in tf:
            # Do not skip metadata here
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
