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
import pydantic

import atr.tasks.checks as checks

_LOGGER: Final = logging.getLogger(__name__)


class Check(pydantic.BaseModel):
    """Parameters for file hash checking."""

    release_name: str = pydantic.Field(..., description="Release name")
    abs_path: str = pydantic.Field(..., description="Absolute path to the file to check")
    abs_hash_file: str = pydantic.Field(..., description="Absolute path to the hash file")
    algorithm: str = pydantic.Field(..., description="Hash algorithm to use")


@checks.with_model(Check)
async def check(args: Check) -> str | None:
    """Check the hash of a file."""
    # This is probably the best idea for the rel_path
    # But we might want to use the artifact instead
    rel_path = checks.rel_path(args.abs_hash_file)
    check_instance = await checks.Check.create(checker=check, release_name=args.release_name, path=rel_path)

    _LOGGER.info(f"Checking hash ({args.algorithm}) for {args.abs_path} against {args.abs_hash_file} (rel: {rel_path})")

    if args.algorithm == "sha256":
        hash_func = hashlib.sha256
    elif args.algorithm == "sha512":
        hash_func = hashlib.sha512
    else:
        await check_instance.failure(f"Unsupported hash algorithm: {args.algorithm}", {"algorithm": args.algorithm})
        return None

    hash_obj = hash_func()
    try:
        async with aiofiles.open(args.abs_path, mode="rb") as f:
            while chunk := await f.read(4096):
                hash_obj.update(chunk)
        computed_hash = hash_obj.hexdigest()

        async with aiofiles.open(args.abs_hash_file) as f:
            expected_hash = await f.read()
        # May be in the format "HASH FILENAME\n"
        # TODO: Check the FILENAME part
        expected_hash = expected_hash.strip().split()[0]

        if secrets.compare_digest(computed_hash, expected_hash):
            await check_instance.success(
                f"Hash ({args.algorithm}) matches expected value",
                {"computed_hash": computed_hash, "expected_hash": expected_hash},
            )
        else:
            await check_instance.failure(
                f"Hash ({args.algorithm}) mismatch",
                {"computed_hash": computed_hash, "expected_hash": expected_hash},
            )
    except Exception as e:
        await check_instance.failure("Unable to verify hash", {"error": str(e)})
    return None
