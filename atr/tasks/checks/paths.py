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
import pathlib
import re
from typing import Final

import aiofiles.os
import pydantic

import atr.analysis as analysis
import atr.tasks.checks as checks
import atr.util as util

_LOGGER: Final = logging.getLogger(__name__)


class Check(pydantic.BaseModel):
    """Arguments for the path structure and naming convention check."""

    release_name: str = pydantic.Field(..., description="Name of the release being checked")
    base_release_dir: str = pydantic.Field(..., description="Absolute path to the base directory of the release draft")


async def _check_artifact_rules(base_path: pathlib.Path, relative_path: pathlib.Path, errors: list[str]) -> None:
    """Check rules specific to artifact files."""
    full_path = base_path / relative_path

    # RDP says that .asc is required
    asc_path = full_path.with_suffix(full_path.suffix + ".asc")
    if not await aiofiles.os.path.exists(asc_path):
        errors.append(f"Missing corresponding signature file ({relative_path}.asc)")

    # RDP requires one of .sha256 or .sha512
    sha256_path = full_path.with_suffix(full_path.suffix + ".sha256")
    sha512_path = full_path.with_suffix(full_path.suffix + ".sha512")
    has_sha256 = await aiofiles.os.path.exists(sha256_path)
    has_sha512 = await aiofiles.os.path.exists(sha512_path)
    if not (has_sha256 or has_sha512):
        errors.append(f"Missing corresponding checksum file ({relative_path}.sha256 or .sha512)")


async def _check_metadata_rules(
    base_path: pathlib.Path, relative_path: pathlib.Path, ext_metadata: str, errors: list[str], warnings: list[str]
) -> None:
    """Check rules specific to metadata files (.asc, .sha*, etc.)."""
    suffixes = set(relative_path.suffixes)

    if ".md5" in suffixes:
        # Forbidden by RCP, deprecated by RDP
        errors.append("The use of .md5 is forbidden, please use .sha512")
    if ".sha1" in suffixes:
        # Deprecated by RDP
        warnings.append("The use of .sha1 is deprecated, please use .sha512")
    if ".sha" in suffixes:
        # Discouraged by RDP
        warnings.append("The use of .sha is discouraged, please use .sha512")
    if ".sig" in suffixes:
        # Forbidden by RCP, forbidden by RDP
        errors.append("Binary signature files (.sig) are forbidden, please use .asc")

    # "Signature and checksum files for verifying distributed artifacts should
    # not be provided, unless named as indicated above." (RDP)
    # Also .mds is allowed, but we'll ignore that for now
    # TODO: Is .mds supported in analysis.METADATA_SUFFIXES?
    if ext_metadata not in {".asc", ".sha256", ".sha512", ".md5", ".sha", ".sha1"}:
        warnings.append("The use of this metadata file is discouraged")

    # Check whether the corresponding artifact exists
    artifact_path_base = str(relative_path).removesuffix(ext_metadata)
    full_artifact_path = base_path / artifact_path_base
    if not await aiofiles.os.path.exists(full_artifact_path):
        errors.append(f"Metadata file exists but corresponding artifact '{artifact_path_base}' is missing")


async def _check_path_process_single(
    base_path: pathlib.Path,
    relative_path: pathlib.Path,
    check_errors: checks.Check,
    check_warnings: checks.Check,
    check_success: checks.Check,
) -> None:
    """Process and check a single path within the release directory."""
    full_path = base_path / relative_path
    relative_path_str = str(relative_path)

    errors: list[str] = []
    warnings: list[str] = []

    # The Release Distribution Policy specifically allows README and CHANGES, etc.
    # We assume that LICENSE and NOTICE are permitted also
    if relative_path.name == "KEYS":
        errors.append("The KEYS file should be uploaded via the 'Keys' section, not included in the artifact bundle")
    if any(part.startswith(".") for part in relative_path.parts):
        # TODO: There is not a a policy for this
        # We should enquire as to whether such a policy should be instituted
        # We're forbidding dotfiles to catch accidental uploads of e.g. .git or .htaccess
        # Such cases are likely to be in error, and could carry security risks
        errors.append("Dotfiles are forbidden")

    search = re.search(analysis.extension_pattern(), relative_path_str)
    ext_artifact = search.group("artifact") if search else None
    ext_metadata = search.group("metadata") if search else None

    if ext_artifact:
        _LOGGER.info("Checking artifact rules for %s", full_path)
        await _check_artifact_rules(base_path, relative_path, errors)
    elif ext_metadata:
        _LOGGER.info("Checking metadata rules for %s", full_path)
        await _check_metadata_rules(base_path, relative_path, ext_metadata, errors, warnings)
    else:
        _LOGGER.info("Checking general rules for %s", full_path)
        allowed_top_level = {"LICENSE", "NOTICE", "README", "CHANGES"}
        if (relative_path.parent == pathlib.Path(".")) and (relative_path.name not in allowed_top_level):
            warnings.append(f"Unknown top level file: {relative_path.name}")

    # Must aggregate errors and aggregate warnings otherwise they will be removed by afresh=True
    # Alternatively we could call Check.clear() manually
    if errors:
        await check_errors.failure("; ".join(errors), {"errors": errors}, path=relative_path_str)
    if warnings:
        await check_warnings.warning("; ".join(warnings), {"warnings": warnings}, path=relative_path_str)
    if not (errors or warnings):
        await check_success.success(
            "Path structure and naming conventions conform to policy", {}, path=relative_path_str
        )


@checks.with_model(Check)
async def check(args: Check) -> None:
    """Check file path structure and naming conventions against ASF release policy for all files in a release."""
    # We refer to the following authoritative policies:
    # - Release Creation Process (RCP)
    # - Release Distribution Policy (RDP)
    base_path = pathlib.Path(args.base_release_dir)

    if not await aiofiles.os.path.isdir(base_path):
        _LOGGER.error("Base release directory does not exist or is not a directory: %s", base_path)
        return

    check_errors = await checks.Check.create(
        checker=checks.function_key(check) + "_errors", release_name=args.release_name, path=None, afresh=True
    )
    check_warnings = await checks.Check.create(
        checker=checks.function_key(check) + "_warnings", release_name=args.release_name, path=None, afresh=True
    )
    check_success = await checks.Check.create(
        checker=checks.function_key(check) + "_success", release_name=args.release_name, path=None, afresh=True
    )
    relative_paths = await util.paths_recursive(base_path)

    for relative_path in relative_paths:
        # Delegate processing of each path to the helper function
        await _check_path_process_single(
            base_path,
            relative_path,
            check_errors,
            check_warnings,
            check_success,
        )

    return None
