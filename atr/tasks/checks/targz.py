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
import os.path
import tarfile
from typing import Final

import pydantic

import atr.tasks.checks as checks

_LOGGER: Final = logging.getLogger(__name__)


class Integrity(pydantic.BaseModel):
    """Parameters for archive integrity checking."""

    release_name: str = pydantic.Field(..., description="Release name")
    abs_path: str = pydantic.Field(..., description="Absolute path to the .tar.gz file to check")
    chunk_size: int = pydantic.Field(default=4096, description="Size of chunks to read when checking the file")


@checks.with_model(Integrity)
async def integrity(args: Integrity) -> str | None:
    """Check the integrity of a .tar.gz file."""
    rel_path = checks.rel_path(args.abs_path)
    _LOGGER.info(f"ABS, REL: {args.abs_path} {rel_path}")
    check = await checks.Check.create(checker=integrity, release_name=args.release_name, path=rel_path)
    try:
        size = await asyncio.to_thread(_integrity_core, args.abs_path, args.chunk_size)
        await check.success("Able to read all entries of the archive using tarfile", {"size": size})
    except Exception as e:
        await check.failure("Unable to read all entries of the archive using tarfile", {"error": str(e)})
    return None


@checks.with_model(checks.ReleaseAndAbsPath)
async def structure(args: checks.ReleaseAndAbsPath) -> str | None:
    """Check the structure of a .tar.gz file."""
    rel_path = checks.rel_path(args.abs_path)
    check = await checks.Check.create(checker=structure, release_name=args.release_name, path=rel_path)
    filename = os.path.basename(args.abs_path)
    expected_root: Final[str] = os.path.splitext(os.path.splitext(filename)[0])[0]
    _LOGGER.info(f"Checking structure for {args.abs_path} (expected root: {expected_root})")

    try:
        root = await asyncio.to_thread(root_directory, args.abs_path)
        if root == expected_root:
            await check.success(
                "Archive contains exactly one root directory matching the expected name",
                {"root": root, "expected": expected_root},
            )
        else:
            await check.failure(
                f"Root directory '{root}' does not match expected name '{expected_root}'",
                {"root": root, "expected": expected_root},
            )
    except Exception as e:
        await check.failure("Unable to verify archive structure", {"error": str(e)})
    return None


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
                    raise ValueError(f"Multiple root directories found: {root}, {parts[0]}")

    if not root:
        raise ValueError("No root directory found in archive")

    return root


def _integrity_core(tgz_path: str, chunk_size: int = 4096) -> int:
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
