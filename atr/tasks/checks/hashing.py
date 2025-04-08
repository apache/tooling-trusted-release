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
from typing import Final

import aiofiles

import atr.tasks.checks as checks

_LOGGER: Final = logging.getLogger(__name__)


@checks.with_model(checks.ReleaseAndRelPath)
async def check(args: checks.ReleaseAndRelPath) -> str | None:
    """Check the hash of a file."""
    check_obj = await checks.Check.create(
        checker=check, release_name=args.release_name, primary_rel_path=args.primary_rel_path
    )

    if not (hash_abs_path := await check_obj.abs_path()):
        return None

    algorithm = hash_abs_path.suffix.lstrip(".")
    if algorithm not in {"sha256", "sha512"}:
        await check_obj.failure("Unsupported hash algorithm", {"algorithm": algorithm})
        return None

    # Remove the hash file suffix to get the artifact path
    # This replaces the last suffix, which is what we want
    # >>> pathlib.Path("a/b/c.d.e.f.g").with_suffix(".x")
    # PosixPath('a/b/c.d.e.f.x')
    # >>> pathlib.Path("a/b/c.d.e.f.g").with_suffix("")
    # PosixPath('a/b/c.d.e.f')
    artifact_abs_path = hash_abs_path.with_suffix("")

    _LOGGER.info(
        f"Checking hash ({algorithm}) for {artifact_abs_path} against {hash_abs_path} (rel: {args.primary_rel_path})"
    )

    hash_func = hashlib.sha256 if algorithm == "sha256" else hashlib.sha512
    hash_obj = hash_func()
    try:
        async with aiofiles.open(artifact_abs_path, mode="rb") as f:
            while chunk := await f.read(4096):
                hash_obj.update(chunk)
        computed_hash = hash_obj.hexdigest()

        async with aiofiles.open(hash_abs_path) as f:
            expected_hash = await f.read()
        # May be in the format "HASH FILENAME\n"
        # TODO: Check the FILENAME part
        expected_hash = expected_hash.strip().split()[0]

        if secrets.compare_digest(computed_hash, expected_hash):
            await check_obj.success(
                f"Hash ({algorithm}) matches expected value",
                {"computed_hash": computed_hash, "expected_hash": expected_hash},
            )
        else:
            await check_obj.failure(
                f"Hash ({algorithm}) mismatch",
                {"computed_hash": computed_hash, "expected_hash": expected_hash},
            )
    except Exception as e:
        await check_obj.failure("Unable to verify hash", {"error": str(e)})
    return None
