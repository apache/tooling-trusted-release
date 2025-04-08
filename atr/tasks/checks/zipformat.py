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
import os
import zipfile
from typing import Any

import atr.tasks.checks as checks
import atr.tasks.checks.license as license

_LOGGER = logging.getLogger(__name__)


@checks.with_model(checks.ReleaseAndRelPath)
async def integrity(args: checks.ReleaseAndRelPath) -> str | None:
    """Check that the zip archive is not corrupted and can be opened."""
    check = await checks.Check.create(
        checker=integrity, release_name=args.release_name, primary_rel_path=args.primary_rel_path
    )
    if not (artifact_abs_path := await check.abs_path()):
        return None

    _LOGGER.info(f"Checking zip integrity for {artifact_abs_path} (rel: {args.primary_rel_path})")

    try:
        result_data = await asyncio.to_thread(_integrity_check_core_logic, str(artifact_abs_path))
        if result_data.get("error"):
            await check.failure(result_data["error"], result_data)
        else:
            await check.success(f"Zip archive integrity OK ({result_data['member_count']} members)", result_data)
    except Exception as e:
        await check.failure("Error checking zip integrity", {"error": str(e)})

    return None


@checks.with_model(checks.ReleaseAndRelPath)
async def license_files(args: checks.ReleaseAndRelPath) -> str | None:
    """Check that the LICENSE and NOTICE files exist and are valid within the zip."""
    check = await checks.Check.create(
        checker=license_files, release_name=args.release_name, primary_rel_path=args.primary_rel_path
    )
    if not (artifact_abs_path := await check.abs_path()):
        return None

    _LOGGER.info(f"Checking zip license files for {artifact_abs_path} (rel: {args.primary_rel_path})")

    try:
        result_data = await asyncio.to_thread(_license_files_check_core_logic_zip, str(artifact_abs_path))

        if result_data.get("error"):
            await check.failure(result_data["error"], result_data)
        elif result_data.get("license_valid") and result_data.get("notice_valid"):
            await check.success("LICENSE and NOTICE files present and valid in zip", result_data)
        else:
            issues = []
            if not result_data.get("license_found"):
                issues.append("LICENSE missing")
            elif not result_data.get("license_valid"):
                issues.append("LICENSE invalid or empty")
            if not result_data.get("notice_found"):
                issues.append("NOTICE missing")
            elif not result_data.get("notice_valid"):
                issues.append("NOTICE invalid or empty")
            issue_str = ", ".join(issues) if issues else "Issues found with LICENSE or NOTICE files"
            await check.failure(issue_str, result_data)

    except Exception as e:
        await check.failure("Error checking zip license files", {"error": str(e)})

    return None


@checks.with_model(checks.ReleaseAndRelPath)
async def license_headers(args: checks.ReleaseAndRelPath) -> str | None:
    """Check that all source files within the zip have valid license headers."""
    check = await checks.Check.create(
        checker=license_headers, release_name=args.release_name, primary_rel_path=args.primary_rel_path
    )
    if not (artifact_abs_path := await check.abs_path()):
        return None

    _LOGGER.info(f"Checking zip license headers for {artifact_abs_path} (rel: {args.primary_rel_path})")

    try:
        result_data = await asyncio.to_thread(_license_headers_check_core_logic_zip, str(artifact_abs_path))

        if result_data.get("error_message"):
            await check.failure(result_data["error_message"], result_data)
        elif not result_data.get("valid"):
            num_issues = len(result_data.get("files_without_headers", []))
            failure_msg = f"{num_issues} file(s) missing or having invalid license headers"
            await check.failure(failure_msg, result_data)
        else:
            await check.success(
                f"License headers OK ({result_data.get('files_checked', 0)} files checked)", result_data
            )

    except Exception as e:
        await check.failure("Error checking zip license headers", {"error": str(e)})

    return None


@checks.with_model(checks.ReleaseAndRelPath)
async def structure(args: checks.ReleaseAndRelPath) -> str | None:
    """Check that the zip archive has a single root directory matching the artifact name."""
    check = await checks.Check.create(
        checker=structure, release_name=args.release_name, primary_rel_path=args.primary_rel_path
    )
    if not (artifact_abs_path := await check.abs_path()):
        return None

    _LOGGER.info(f"Checking zip structure for {artifact_abs_path} (rel: {args.primary_rel_path})")

    try:
        result_data = await asyncio.to_thread(_structure_check_core_logic, str(artifact_abs_path))
        if result_data.get("error"):
            await check.failure(result_data["error"], result_data)
        else:
            await check.success(f"Zip structure OK (root: {result_data['root_dir']})", result_data)
    except Exception as e:
        await check.failure("Error checking zip structure", {"error": str(e)})

    return None


def _integrity_check_core_logic(artifact_path: str) -> dict[str, Any]:
    """Verify that a zip file can be opened and its members listed."""
    try:
        with zipfile.ZipFile(artifact_path, "r") as zf:
            # This is a simple check using list members
            # We can use zf.testzip() for CRC checks if needed, though this will be slower
            member_list = zf.namelist()
            return {"member_count": len(member_list)}
    except zipfile.BadZipFile as e:
        return {"error": f"Bad zip file: {e}"}
    except FileNotFoundError:
        return {"error": "File not found"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


def _license_files_check_file_zip(zf: zipfile.ZipFile, artifact_path: str, expected_path: str) -> tuple[bool, bool]:
    """Check for the presence and basic validity of a specific file in a zip."""
    found = False
    valid = False
    try:
        with zf.open(expected_path) as file_handle:
            found = True
            content = file_handle.read().strip()
            if content:
                # TODO: Add more specific NOTICE checks if needed
                valid = True
    except KeyError:
        # File not found in zip
        ...
    except Exception as e:
        filename = os.path.basename(expected_path)
        _LOGGER.warning(f"Error reading {filename} in zip {artifact_path}: {e}")
    return found, valid


def _license_files_check_core_logic_zip(artifact_path: str) -> dict[str, Any]:
    """Verify LICENSE and NOTICE files within a zip archive."""
    # TODO: Obviously we want to reuse the license files check logic from license.py
    # But we'd need to have task dependencies to do that, ideally
    try:
        with zipfile.ZipFile(artifact_path, "r") as zf:
            members = zf.namelist()
            if not members:
                return {"error": "Archive is empty"}

            root_dir = _license_files_find_root_dir_zip(members)
            if not root_dir:
                return {"error": "Could not determine root directory"}

            expected_license_path = root_dir + "LICENSE"
            expected_notice_path = root_dir + "NOTICE"

            member_set = set(members)

            license_found, license_valid = (
                _license_files_check_file_zip(zf, artifact_path, expected_license_path)
                if (expected_license_path in member_set)
                else (False, False)
            )
            notice_found, notice_valid = (
                _license_files_check_file_zip(zf, artifact_path, expected_notice_path)
                if (expected_notice_path in member_set)
                else (False, False)
            )

            return {
                "root_dir": root_dir,
                "license_found": license_found,
                "license_valid": license_valid,
                "notice_found": notice_found,
                "notice_valid": notice_valid,
            }

    except zipfile.BadZipFile as e:
        return {"error": f"Bad zip file: {e}"}
    except FileNotFoundError:
        return {"error": "File not found"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


def _license_files_find_root_dir_zip(members: list[str]) -> str | None:
    """Find the root directory in a list of zip members."""
    for member in members:
        if "/" in member:
            return member.split("/", 1)[0]
    return None


def _license_headers_check_core_logic_zip(artifact_path: str) -> dict[str, Any]:
    """Verify license headers for files within a zip archive."""
    files_checked = 0
    files_with_issues: list[str] = []
    try:
        with zipfile.ZipFile(artifact_path, "r") as zf:
            members = zf.infolist()

            for member_info in members:
                if member_info.is_dir():
                    continue

                member_path = member_info.filename
                _, extension = os.path.splitext(member_path)
                extension = extension.lower().lstrip(".")

                if not _license_headers_check_should_check_zip(member_path, extension):
                    continue

                files_checked += 1
                is_valid, error_msg = _license_headers_check_single_file_zip(zf, member_info, extension)

                if error_msg:
                    # Already includes path and error type
                    files_with_issues.append(error_msg)
                elif not is_valid:
                    # Just append path for header mismatch
                    files_with_issues.append(member_path)

            if files_with_issues:
                return {
                    "valid": False,
                    "files_checked": files_checked,
                    "files_without_headers": files_with_issues,
                    "error_message": None,
                }
            else:
                return {
                    "valid": True,
                    "files_checked": files_checked,
                    "files_without_headers": [],
                    "error_message": None,
                }

    except zipfile.BadZipFile as e:
        return {"valid": False, "error_message": f"Bad zip file: {e}"}
    except FileNotFoundError:
        return {"valid": False, "error_message": "File not found"}
    except Exception as e:
        return {"valid": False, "error_message": f"Unexpected error: {e}"}


def _license_headers_check_should_check_zip(member_path: str, extension: str) -> bool:
    """Determine whether a file in a zip should be checked for license headers."""
    for pattern in license.INCLUDED_PATTERNS:
        if license.re.match(pattern, f".{extension}"):
            # Also check whether we have a comment style defined for it
            if license.COMMENT_STYLES.get(extension):
                return True
            else:
                _LOGGER.warning(f"No comment style defined for included extension '{extension}' in {member_path}")
                return False
    return False


def _license_headers_check_single_file_zip(
    zf: zipfile.ZipFile, member_info: zipfile.ZipInfo, extension: str
) -> tuple[bool, str | None]:
    """Check the license header of a single file within a zip. Returns (is_valid, error_message)."""
    member_path = member_info.filename
    try:
        with zf.open(member_path) as file_in_zip:
            content_bytes = file_in_zip.read(2048)
            header_bytes = license.strip_comments(content_bytes, extension)
            expected_header_bytes = license.APACHE_LICENSE_HEADER
            if header_bytes == expected_header_bytes:
                return True, None
            else:
                # Header mismatch
                return False, None
    except Exception as read_error:
        return False, f"{member_path} (Read Error: {read_error})"


def _structure_check_core_logic(artifact_path: str) -> dict[str, Any]:
    """Verify the internal structure of the zip archive."""
    try:
        with zipfile.ZipFile(artifact_path, "r") as zf:
            members = zf.namelist()
            if not members:
                return {"error": "Archive is empty"}

            base_name = os.path.basename(artifact_path)
            name_part = base_name.removesuffix(".zip")
            # # TODO: Airavata has e.g. "-source-release"
            # # It would be useful if there were a function in analysis.py for stripping these
            # # But the root directory should probably always match the name of the file sans suffix
            # # (This would also be easier to implement)
            # if name_part.endswith(("-src", "-bin", "-dist")):
            #     name_part = "-".join(name_part.split("-")[:-1])
            expected_root = name_part

            root_dirs, non_rooted_files = _structure_check_core_logic_find_roots(zf, members)
            actual_root, error_msg = _structure_check_core_logic_validate_root(
                members, root_dirs, non_rooted_files, expected_root
            )

            if error_msg:
                return {"error": error_msg}
            if actual_root:
                return {"root_dir": actual_root}
            return {"error": "Unknown structure validation error"}

    except zipfile.BadZipFile as e:
        return {"error": f"Bad zip file: {e}"}
    except FileNotFoundError:
        return {"error": "File not found"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


def _structure_check_core_logic_find_roots(zf: zipfile.ZipFile, members: list[str]) -> tuple[set[str], list[str]]:
    """Identify root directories and non-rooted files in a zip archive."""
    root_dirs: set[str] = set()
    non_rooted_files: list[str] = []
    for member in members:
        if "/" in member:
            root_dirs.add(member.split("/", 1)[0])
        elif not zipfile.Path(zf, member).is_dir():
            non_rooted_files.append(member)
    return root_dirs, non_rooted_files


def _structure_check_core_logic_validate_root(
    members: list[str], root_dirs: set[str], non_rooted_files: list[str], expected_root: str
) -> tuple[str | None, str | None]:
    """Validate the identified root structure against expectations."""
    if non_rooted_files:
        return None, f"Files found directly in root: {non_rooted_files}"
    if not root_dirs:
        return None, "No directories found in archive"
    if len(root_dirs) > 1:
        return None, f"Multiple root directories found: {sorted(list(root_dirs))}"

    actual_root = next(iter(root_dirs))
    if actual_root != expected_root:
        return None, f"Root directory mismatch. Expected '{expected_root}', found '{actual_root}'"

    # Check whether all members are under the correct root directory
    for member in members:
        if member == actual_root.rstrip("/"):
            continue
        if not member.startswith(expected_root):
            return None, f"Member found outside expected root directory: {member}"

    return actual_root, None
