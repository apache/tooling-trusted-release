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
import pathlib
import re

import aiofiles.os

import atr.analysis as analysis
import atr.log as log
import atr.models.results as results
import atr.tasks.checks as checks
import atr.util as util

_ALLOWED_TOP_LEVEL = {"CHANGES", "LICENSE", "NOTICE", "README"}


async def check(args: checks.FunctionArguments) -> results.Results | None:
    """Check file path structure and naming conventions against ASF release policy for all files in a release."""
    # We refer to the following authoritative policies:
    # - Release Creation Process (RCP)
    # https://infra.apache.org/release-publishing.html
    # - Release Distribution Policy (RDP)
    # https://infra.apache.org/release-distribution.html
    # - Incubation Policy (IP)
    # https://incubator.apache.org/policy/incubation.html

    recorder_errors = await checks.Recorder.create(
        checker=checks.function_key(check) + "_errors",
        project_name=args.project_name,
        version_name=args.version_name,
        revision_number=args.revision_number,
        primary_rel_path=None,
        afresh=True,
    )
    recorder_warnings = await checks.Recorder.create(
        checker=checks.function_key(check) + "_warnings",
        project_name=args.project_name,
        version_name=args.version_name,
        revision_number=args.revision_number,
        primary_rel_path=None,
        afresh=True,
    )
    recorder_success = await checks.Recorder.create(
        checker=checks.function_key(check) + "_success",
        project_name=args.project_name,
        version_name=args.version_name,
        revision_number=args.revision_number,
        primary_rel_path=None,
        afresh=True,
    )

    # As primary_rel_path is None, the base path is the release candidate draft directory
    if not (base_path := await recorder_success.abs_path()):
        return

    if not await aiofiles.os.path.isdir(base_path):
        log.error("Base release directory does not exist or is not a directory: %s", base_path)
        return

    is_podling = args.extra_args.get("is_podling", False)
    relative_paths = [p async for p in util.paths_recursive(base_path)]
    relative_paths_set = set(str(p) for p in relative_paths)
    for relative_path in relative_paths:
        # Delegate processing of each path to the helper function
        await _check_path_process_single(
            base_path,
            relative_path,
            recorder_errors,
            recorder_warnings,
            recorder_success,
            relative_paths_set,
            is_podling,
        )

    return None


async def _check_artifact_rules(
    base_path: pathlib.Path, relative_path: pathlib.Path, relative_paths: set[str], errors: list[str], is_podling: bool
) -> None:
    """Check rules specific to artifact files."""
    full_path = base_path / relative_path

    # RDP says that .asc is required
    asc_path = full_path.with_suffix(full_path.suffix + ".asc")
    if not await aiofiles.os.path.exists(asc_path):
        errors.append(f"Missing corresponding signature file ({relative_path}.asc)")

    # RDP requires one of .sha256 or .sha512
    relative_sha256_path = relative_path.with_suffix(relative_path.suffix + ".sha256")
    relative_sha512_path = relative_path.with_suffix(relative_path.suffix + ".sha512")
    has_sha256 = str(relative_sha256_path) in relative_paths
    has_sha512 = str(relative_sha512_path) in relative_paths
    if not (has_sha256 or has_sha512):
        errors.append(f"Missing corresponding checksum file ({relative_path}.sha256 or {relative_path}.sha512)")

    # IP requires "incubating" in the filename
    if is_podling is True:
        # TODO: Allow "incubator" too as #114 requests?
        if "incubating" not in full_path.name:
            errors.append("Podling artifact filenames must include 'incubating'")


async def _check_metadata_rules(
    _base_path: pathlib.Path,
    relative_path: pathlib.Path,
    relative_paths: set[str],
    ext_metadata: str,
    errors: list[str],
    warnings: list[str],
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
    if artifact_path_base not in relative_paths:
        errors.append(f"Metadata file exists but corresponding artifact '{artifact_path_base}' is missing")


async def _check_path_process_single(
    base_path: pathlib.Path,
    relative_path: pathlib.Path,
    recorder_errors: checks.Recorder,
    recorder_warnings: checks.Recorder,
    recorder_success: checks.Recorder,
    relative_paths: set[str],
    is_podling: bool,
) -> None:
    """Process and check a single path within the release directory."""
    full_path = base_path / relative_path
    relative_path_str = str(relative_path)

    # For debugging and testing
    # TODO: Scope this to admin users
    if full_path.name == "deliberately_slow_ATR_task_filename.txt":
        await asyncio.sleep(20)

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

    allowed_top_level = _ALLOWED_TOP_LEVEL
    if ext_artifact:
        log.info("Checking artifact rules for %s", full_path)
        await _check_artifact_rules(base_path, relative_path, relative_paths, errors, is_podling)
    elif ext_metadata:
        log.info("Checking metadata rules for %s", full_path)
        await _check_metadata_rules(base_path, relative_path, relative_paths, ext_metadata, errors, warnings)
    else:
        log.info("Checking general rules for %s", full_path)
        if (relative_path.parent == pathlib.Path(".")) and (relative_path.name not in allowed_top_level):
            warnings.append(f"Unknown top level file: {relative_path.name}")

    for error in errors:
        await recorder_errors.failure(error, {}, primary_rel_path=relative_path_str)
    for warning in warnings:
        await recorder_warnings.warning(warning, {}, primary_rel_path=relative_path_str)
    if not (errors or warnings):
        await recorder_success.success(
            "Path structure and naming conventions conform to policy", {}, primary_rel_path=relative_path_str
        )
