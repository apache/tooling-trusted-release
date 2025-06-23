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
from typing import Any, Final

import atr.tasks.checks as checks

_LOGGER: Final = logging.getLogger(__name__)


async def integrity(args: checks.FunctionArguments) -> str | None:
    """Check that the zip archive is not corrupted and can be opened."""
    recorder = await args.recorder()
    if not (artifact_abs_path := await recorder.abs_path()):
        return None

    _LOGGER.info(f"Checking zip integrity for {artifact_abs_path} (rel: {args.primary_rel_path})")

    try:
        result_data = await asyncio.to_thread(_integrity_check_core_logic, str(artifact_abs_path))
        if result_data.get("error"):
            await recorder.failure(result_data["error"], result_data)
        else:
            await recorder.success(f"Zip archive integrity OK ({result_data['member_count']} members)", result_data)
    except Exception as e:
        await recorder.failure("Error checking zip integrity", {"error": str(e)})

    return None


async def structure(args: checks.FunctionArguments) -> str | None:
    """Check that the zip archive has a single root directory matching the artifact name."""
    recorder = await args.recorder()
    if not (artifact_abs_path := await recorder.abs_path()):
        return None
    if await recorder.primary_path_is_binary():
        return None

    _LOGGER.info(f"Checking zip structure for {artifact_abs_path} (rel: {args.primary_rel_path})")

    try:
        result_data = await asyncio.to_thread(_structure_check_core_logic, str(artifact_abs_path))

        if result_data.get("warning"):
            await recorder.warning(result_data["warning"], result_data)
        elif result_data.get("error"):
            await recorder.failure(result_data["error"], result_data)
        else:
            await recorder.success(f"Zip structure OK (root: {result_data['root_dir']})", result_data)
    except Exception as e:
        await recorder.failure("Error checking zip structure", {"error": str(e)})

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
                if error_msg.startswith("Root directory mismatch"):
                    return {"warning": error_msg}
                else:
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
