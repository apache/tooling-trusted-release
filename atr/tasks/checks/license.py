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
import hashlib
import logging
import os
import re
import tarfile
from collections.abc import Iterator
from typing import Any, Final

import atr.tasks.checks as checks
from atr import schema
from atr.db import models

_LOGGER: Final = logging.getLogger(__name__)


# Constant that must be present in the Apache License header
APACHE_LICENSE_HEADER: Final[bytes] = b"""\
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License."""


# File type comment style definitions
# Ordered by their popularity in the Stack Overflow Developer Survey 2024
COMMENT_STYLES: Final[dict[str, dict[str, str]]] = {
    # JavaScript and variants
    "js": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "mjs": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "cjs": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "jsx": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # Python
    "py": {"single": "#", "multi_start": '"""', "multi_end": '"""'},
    # SQL
    "sql": {"single": "--", "multi_start": "/*", "multi_end": "*/"},
    "ddl": {"single": "--", "multi_start": "/*", "multi_end": "*/"},
    "dml": {"single": "--", "multi_start": "/*", "multi_end": "*/"},
    # TypeScript and variants
    "ts": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "tsx": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "mts": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "cts": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # Shell scripts
    "sh": {"single": "#"},
    "bash": {"single": "#"},
    "zsh": {"single": "#"},
    "ksh": {"single": "#"},
    # Java
    "java": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "jav": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # C#
    "cs": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "csx": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # C++
    "cpp": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "cxx": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "cc": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "hpp": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # C
    "c": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "h": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # PHP
    "php": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "phtml": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # PowerShell
    "ps1": {"single": "#", "multi_start": "<#", "multi_end": "#>"},
    "psm1": {"single": "#", "multi_start": "<#", "multi_end": "#>"},
    "psd1": {"single": "#", "multi_start": "<#", "multi_end": "#>"},
    # Go
    "go": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # Rust
    "rs": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # Kotlin
    "kt": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "kts": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # Lua
    "lua": {"single": "--", "multi_start": "--[[", "multi_end": "]]"},
    # Dart
    "dart": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # Assembly
    "asm": {"single": ";"},
    "s": {"single": "#"},
    "S": {"single": "#"},
    # Ruby
    "rb": {"single": "#", "multi_start": "=begin", "multi_end": "=end"},
    "rbw": {"single": "#", "multi_start": "=begin", "multi_end": "=end"},
    # Swift
    "swift": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # R
    "r": {"single": "#"},
    "R": {"single": "#"},
    # Visual Basic
    "vb": {"single": "'", "multi_start": "/*", "multi_end": "*/"},
    "vbs": {"single": "'", "multi_start": "/*", "multi_end": "*/"},
    # MATLAB
    "m": {"single": "%", "multi_start": "%{", "multi_end": "%}"},
    # VBA
    "vba": {"single": "'"},
    # Groovy
    "groovy": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "gvy": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "gy": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "gsh": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # Scala
    "scala": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    "sc": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
    # Perl
    "pl": {"single": "#", "multi_start": "=pod", "multi_end": "=cut"},
    "pm": {"single": "#", "multi_start": "=pod", "multi_end": "=cut"},
    "t": {"single": "#", "multi_start": "=pod", "multi_end": "=cut"},
}

# Patterns for files to include in license header checks
# Ordered by their popularity in the Stack Overflow Developer Survey 2024
INCLUDED_PATTERNS: Final[list[str]] = [
    r"\.(js|mjs|cjs|jsx)$",  # JavaScript
    r"\.py$",  # Python
    r"\.(sql|ddl|dml)$",  # SQL
    r"\.(ts|tsx|mts|cts)$",  # TypeScript
    r"\.(sh|bash|zsh|ksh)$",  # Shell
    r"\.(java|jav)$",  # Java
    r"\.(cs|csx)$",  # C#
    r"\.(cpp|cxx|cc|c\+\+|hpp)$",  # C++
    r"\.(c|h)$",  # C
    r"\.(php|php[3-9]|phtml)$",  # PHP
    r"\.(ps1|psm1|psd1)$",  # PowerShell
    r"\.go$",  # Go
    r"\.rs$",  # Rust
    r"\.(kt|kts)$",  # Kotlin
    r"\.(lua)$",  # Lua
    r"\.dart$",  # Dart
    r"\.(asm|s|S)$",  # Assembly
    r"\.(rb|rbw)$",  # Ruby
    r"\.swift$",  # Swift
    r"\.(r|R)$",  # R
    r"\.(vb|vbs)$",  # Visual Basic
    r"\.m$",  # MATLAB
    r"\.vba$",  # VBA
    r"\.(groovy|gvy|gy|gsh)$",  # Groovy
    r"\.(scala|sc)$",  # Scala
    r"\.(pl|pm|t)$",  # Perl
]

# Types


class ArtifactData(schema.Strict):
    files_checked: int = schema.default(0)
    files_with_valid_headers: int = schema.default(0)
    files_with_invalid_headers: int = schema.default(0)
    files_skipped: int = schema.default(0)


class ArtifactResult(schema.Strict):
    status: models.CheckResultStatus
    message: str
    data: Any = schema.Field(default=None)


# class LicenseCheckResult(schema.Strict):
#     files_checked: list[str]
#     files_with_valid_headers: int
#     errors: list[str]
#     error_message: str | None
#     warning_message: str | None
#     valid: bool


class MemberResult(schema.Strict):
    status: models.CheckResultStatus
    path: str
    message: str
    data: Any = schema.Field(default=None)


class MemberSkippedResult(schema.Strict):
    path: str
    reason: str


Result = ArtifactResult | MemberResult | MemberSkippedResult

# Tasks


async def files(args: checks.FunctionArguments) -> str | None:
    """Check that the LICENSE and NOTICE files exist and are valid."""
    recorder = await args.recorder()
    if not (artifact_abs_path := await recorder.abs_path()):
        return None

    _LOGGER.info(f"Checking license files for {artifact_abs_path} (rel: {args.primary_rel_path})")

    try:
        for result in await asyncio.to_thread(_files_check_core_logic, str(artifact_abs_path)):
            match result:
                case ArtifactResult():
                    await _record_artifact(recorder, result)
                case MemberResult():
                    await _record_member(recorder, result)
                case MemberSkippedResult():
                    pass

    except Exception as e:
        _LOGGER.exception("Error during license file check execution:")
        await recorder.exception("Error during license file check execution", {"error": str(e)})

    return None


async def headers(args: checks.FunctionArguments) -> str | None:
    """Check that all source files have valid license headers."""
    recorder = await args.recorder()
    if not (artifact_abs_path := await recorder.abs_path()):
        return None

    _LOGGER.info(f"Checking license headers for {artifact_abs_path} (rel: {args.primary_rel_path})")

    try:
        for result in await asyncio.to_thread(_headers_check_core_logic, str(artifact_abs_path)):
            match result:
                case ArtifactResult():
                    await _record_artifact(recorder, result)
                case MemberResult():
                    await _record_member(recorder, result)
                case MemberSkippedResult():
                    pass

    except Exception as e:
        await recorder.exception("Error during license header check execution", {"error": str(e)})

    return None


def strip_comments(content: bytes, file_ext: str) -> bytes:
    """Strip comment prefixes from the content based on the file extension."""
    if file_ext not in COMMENT_STYLES:
        return content

    comment_style = COMMENT_STYLES[file_ext]
    lines = content.split(b"\n")
    cleaned_lines = []

    # Get comment markers as bytes
    multi_start = comment_style.get("multi_start", "").encode()
    multi_end = comment_style.get("multi_end", "").encode()
    single = comment_style.get("single", "").encode()

    # State tracking
    in_multiline = False
    is_c_style = (multi_start == b"/*") and (multi_end == b"*/")

    for line in lines:
        line = line.strip()

        # Handle start of multi-line comment
        if not in_multiline and multi_start and multi_start in line:
            # Get content after multi-start
            line = line[line.find(multi_start) + len(multi_start) :].strip()
            in_multiline = True

        # Handle end of multi-line comment
        elif in_multiline and multi_end and multi_end in line:
            # Get content before multi-end
            line = line[: line.find(multi_end)].strip()
            in_multiline = False

        # Handle single-line comments
        elif not in_multiline and single and line.startswith(single):
            line = line[len(single) :].strip()

        # For C style comments, strip leading asterisk if present
        elif is_c_style and in_multiline and line.startswith(b"*"):
            line = line[1:].strip()

        # Only add non-empty lines
        if line:
            cleaned_lines.append(line)

    return b"\n".join(cleaned_lines)


# File helpers


def _files_check_core_logic(artifact_path: str) -> Iterator[Result]:
    """Verify that LICENSE and NOTICE files exist and are placed and formatted correctly."""
    files_found = []
    license_ok = False
    notice_ok = False
    notice_issues: list[str] = []

    # # First find and validate the root directory
    # try:
    #     root_dir = targz.root_directory(artifact_path)
    # except targz.RootDirectoryError as e:
    #     yield ArtifactResult(
    #         status=models.CheckResultStatus.WARNING,
    #         message=f"Could not determine root directory: {e!s}",
    #         data=None,
    #     )
    #     # Continue checking files

    # Check for license files in the root directory
    with tarfile.open(artifact_path, mode="r|gz") as tf:
        for member in tf:
            _LOGGER.warning(f"Checking member: {member.name}")
            if member.name and member.name.split("/")[-1].startswith("._"):
                # Metadata convention
                continue

            if member.name.count("/") > 1:
                # Skip files in subdirectories
                continue

            filename = os.path.basename(member.name)
            if filename in {"LICENSE", "NOTICE"}:
                files_found.append(filename)
                if filename == "LICENSE":
                    # TODO: Check length, should be 11,358 bytes
                    license_ok = _files_check_core_logic_license(tf, member)
                elif filename == "NOTICE":
                    # TODO: Check length doesn't exceed some preset
                    notice_ok, notice_issues = _files_check_core_logic_notice(tf, member)

    yield from _files_messages_build(files_found, license_ok, notice_ok, notice_issues)

    is_valid = license_ok and notice_ok
    yield ArtifactResult(
        status=models.CheckResultStatus.SUCCESS if is_valid else models.CheckResultStatus.FAILURE,
        message="LICENSE and NOTICE files present and valid"
        if is_valid
        else "Issues found with LICENSE or NOTICE files",
        data=None,
    )


def _files_check_core_logic_license(tf: tarfile.TarFile, member: tarfile.TarInfo) -> bool:
    """Verify that the LICENSE file matches the Apache 2.0 license."""
    f = tf.extractfile(member)
    if not f:
        return False

    sha3 = hashlib.sha3_256()
    content = f.read()
    sha3.update(content[:11358])
    return sha3.hexdigest() == "8a0a8fb6c73ef27e4322391c7b28e5b38639e64e58c40a2c7a51cec6e7915a6a"


def _files_check_core_logic_notice(tf: tarfile.TarFile, member: tarfile.TarInfo) -> tuple[bool, list[str]]:
    """Verify that the NOTICE file follows the required format."""
    f = tf.extractfile(member)
    if not f:
        return False, ["Could not read NOTICE file"]

    content = f.read().decode("utf-8")
    issues = []

    if not re.search(r"Apache\s+[\w\-\.]+", content, re.MULTILINE):
        issues.append("missing or invalid Apache product header")
    if not re.search(r"Copyright\s+(?:\d{4}|\d{4}-\d{4})\s+The Apache Software Foundation", content, re.MULTILINE):
        issues.append("missing or invalid copyright statement")
    if not re.search(
        r"This product includes software developed at\s*\nThe Apache Software Foundation \(.*?\)", content, re.DOTALL
    ):
        issues.append("missing or invalid foundation attribution")

    return len(issues) == 0, issues


def _files_messages_build(
    files_found: list[str],
    license_ok: bool,
    notice_ok: bool,
    notice_issues: list[str],
) -> Iterator[Result]:
    """Build status messages for license file verification."""
    if not files_found:
        yield ArtifactResult(
            status=models.CheckResultStatus.FAILURE,
            message="No LICENSE or NOTICE files found",
            data=None,
        )
        return

    # Check the LICENSE file
    if "LICENSE" not in files_found:
        yield ArtifactResult(
            status=models.CheckResultStatus.FAILURE,
            message="LICENSE file not found",
            data=None,
        )
    elif not license_ok:
        yield MemberResult(
            status=models.CheckResultStatus.FAILURE,
            path="LICENSE",
            message="LICENSE file does not match Apache 2.0 license",
            data=None,
        )

    # Check the NOTICE file
    if "NOTICE" not in files_found:
        yield ArtifactResult(
            status=models.CheckResultStatus.FAILURE,
            message="NOTICE file not found",
            data=None,
        )
    elif not notice_ok:
        yield MemberResult(
            status=models.CheckResultStatus.FAILURE,
            path="NOTICE",
            message="NOTICE file format issues: " + "; ".join(notice_issues),
            data=None,
        )


# Header helpers


def _get_file_extension(filename: str) -> str | None:
    """Get the file extension without the dot."""
    _, ext = os.path.splitext(filename)
    if not ext:
        return None
    return ext[1:].lower()


def _headers_check_core_logic(artifact_path: str) -> Iterator[Result]:
    """Verify Apache License headers in source files within an archive."""
    # We could modify @Lucas-C/pre-commit-hooks instead for this
    # But hopefully this will be robust enough, at least for testing
    # First find and validate the root directory
    artifact_data = ArtifactData()

    # try:
    #     targz.root_directory(artifact_path)
    # except targz.RootDirectoryError as e:
    #     # Tooling believes that this should be a warning, not an error
    #     yield ArtifactResult(
    #         status=models.CheckResultStatus.WARNING,
    #         message=f"Could not determine root directory: {e!s}",
    #         data=None,
    #     )

    # Check files in the archive
    with tarfile.open(artifact_path, mode="r|gz") as tf:
        for member in tf:
            if member.name and member.name.split("/")[-1].startswith("._"):
                # Metadata convention
                continue

            match _headers_check_core_logic_process_file(tf, member):
                case ArtifactResult() | MemberResult() as result:
                    artifact_data.files_checked += 1
                    match result.status:
                        case models.CheckResultStatus.SUCCESS:
                            artifact_data.files_with_valid_headers += 1
                        case models.CheckResultStatus.FAILURE:
                            artifact_data.files_with_invalid_headers += 1
                        case models.CheckResultStatus.WARNING:
                            artifact_data.files_with_invalid_headers += 1
                        case models.CheckResultStatus.EXCEPTION:
                            artifact_data.files_with_invalid_headers += 1
                    yield result
                case MemberSkippedResult():
                    artifact_data.files_skipped += 1

    yield ArtifactResult(
        status=models.CheckResultStatus.SUCCESS,
        message=f"Checked {artifact_data.files_checked} files,"
        f" found {artifact_data.files_with_valid_headers} with valid headers,"
        f" {artifact_data.files_with_invalid_headers} with invalid headers,"
        f" and {artifact_data.files_skipped} skipped",
        data=artifact_data.model_dump_json(),
    )


def _headers_check_core_logic_process_file(
    tf: tarfile.TarFile,
    member: tarfile.TarInfo,
) -> Result:
    """Process a single file in an archive for license header verification."""
    if not member.isfile():
        return MemberSkippedResult(
            path=member.name,
            reason="Not a file",
        )

    # Check if we should verify this file, based on extension
    if not _headers_check_core_logic_should_check(member.name):
        return MemberSkippedResult(
            path=member.name,
            reason="Not a source file",
        )

    # Extract and check the file
    try:
        f = tf.extractfile(member)
        if f is None:
            return MemberResult(
                status=models.CheckResultStatus.EXCEPTION,
                path=member.name,
                message="Could not read file",
                data=None,
            )

        # Allow for some extra content at the start of the file
        # That may be shebangs, encoding declarations, etc.
        content = f.read(len(APACHE_LICENSE_HEADER) + 512)
        is_valid, error = _headers_validate(content, member.name)
        if is_valid:
            return MemberResult(
                status=models.CheckResultStatus.SUCCESS,
                path=member.name,
                message="Valid license header",
                data=None,
            )
        else:
            return MemberResult(
                status=models.CheckResultStatus.FAILURE,
                path=member.name,
                message=f"Invalid license header: {error}",
                data=None,
            )
    except Exception as e:
        return MemberResult(
            status=models.CheckResultStatus.EXCEPTION,
            path=member.name,
            message=f"Error processing file: {e!s}",
            data=None,
        )


def _headers_check_core_logic_should_check(filepath: str) -> bool:
    """Determine if a file should be checked for license headers."""
    ext = _get_file_extension(filepath)
    if ext is None:
        return False

    # First check if we have comment style definitions for this extension
    if ext not in COMMENT_STYLES:
        return False

    # Then check if the file matches any of our included patterns
    for pattern in INCLUDED_PATTERNS:
        if re.search(pattern, filepath, re.IGNORECASE):
            return True

    return False


def _headers_validate(content: bytes, filename: str) -> tuple[bool, str | None]:
    """Validate that the content contains the Apache License header after removing comments."""
    # Get the file extension from the filename
    file_ext = _get_file_extension(filename)
    if not file_ext or file_ext not in COMMENT_STYLES:
        return False, "Could not determine file type from extension"

    # Strip comments, removing empty lines in the process
    cleaned_header = strip_comments(content, file_ext)

    # Normalise the expected header in the same way as directly above
    expected_lines = [line.strip() for line in APACHE_LICENSE_HEADER.split(b"\n")]
    expected_lines = [line for line in expected_lines if line]
    expected_header = b"\n".join(expected_lines)

    # Check if the cleaned header contains the expected text
    if expected_header not in cleaned_header:
        # # Find the first difference for debugging
        # cleaned_lines = cleaned_header.split(b"\n")
        # expected_lines = expected_header.split(b"\n")
        # for i, (c, e) in enumerate(zip(cleaned_lines, expected_lines)):
        #     if c != e:
        #         _LOGGER.debug("\nFirst difference at line %d:", i + 1)
        #         _LOGGER.debug("Expected: '%s'", e.decode(errors="replace"))
        #         _LOGGER.debug("Got:      '%s'", c.decode(errors="replace"))
        #         break
        return False, "License header does not match the required Apache License header text"

    return True, None


async def _record_artifact(recorder: checks.Recorder, result: ArtifactResult) -> None:
    match result.status:
        case models.CheckResultStatus.SUCCESS:
            await recorder.success(result.message, result.data)
        case models.CheckResultStatus.WARNING:
            await recorder.warning(result.message, result.data)
        case models.CheckResultStatus.FAILURE:
            await recorder.failure(result.message, result.data)
        case models.CheckResultStatus.EXCEPTION:
            await recorder.exception(result.message, result.data)


async def _record_member(recorder: checks.Recorder, result: MemberResult) -> None:
    match result.status:
        case models.CheckResultStatus.SUCCESS:
            await recorder.success(result.message, result.data, member_rel_path=result.path)
        case models.CheckResultStatus.WARNING:
            await recorder.warning(result.message, result.data, member_rel_path=result.path)
        case models.CheckResultStatus.FAILURE:
            await recorder.failure(result.message, result.data, member_rel_path=result.path)
        case models.CheckResultStatus.EXCEPTION:
            await recorder.exception(result.message, result.data, member_rel_path=result.path)
