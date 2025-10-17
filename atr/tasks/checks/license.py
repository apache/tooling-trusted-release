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
import difflib
import hashlib
import os
import pathlib
import re
from collections.abc import Iterator
from typing import Any, Final

import atr.db as db
import atr.log as log
import atr.models.results as results
import atr.models.schema as schema
import atr.models.sql as sql
import atr.static as static
import atr.tarzip as tarzip
import atr.tasks.checks as checks
import atr.util as util

# Constant that must be present in the Apache License header
HTTP_APACHE_LICENSE_HEADER: Final[bytes] = (
    b"Licensed to the Apache Software Foundation ASF under one or mor"
    b"e contributor license agreements See the NOTICE file distribute"
    b"d with this work for additional information regarding copyright"
    b" ownership The ASF licenses this file to you under the Apache L"
    b"icense Version 2 0 the License you may not use this file except"
    b" in compliance with the License You may obtain a copy of the Li"
    b"cense at http www apache org licenses LICENSE 2 0 Unless requir"
    b"ed by applicable law or agreed to in writing software distribut"
    b"ed under the License"
)

HTTPS_APACHE_LICENSE_HEADER: Final[bytes] = HTTP_APACHE_LICENSE_HEADER.replace(b" http ", b" https ")

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
    status: sql.CheckResultStatus
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
    status: sql.CheckResultStatus
    path: str
    message: str
    data: Any = schema.Field(default=None)


class MemberSkippedResult(schema.Strict):
    path: str
    reason: str


type Result = ArtifactResult | MemberResult | MemberSkippedResult

# Tasks


async def files(args: checks.FunctionArguments) -> results.Results | None:
    """Check that the LICENSE and NOTICE files exist and are valid."""
    recorder = await args.recorder()
    if not (artifact_abs_path := await recorder.abs_path()):
        return None
    if await recorder.primary_path_is_binary():
        return None

    log.info(f"Checking license files for {artifact_abs_path} (rel: {args.primary_rel_path})")

    try:
        is_podling = args.extra_args.get("is_podling", False)
        for result in await asyncio.to_thread(_files_check_core_logic, str(artifact_abs_path), is_podling):
            match result:
                case ArtifactResult():
                    await _record_artifact(recorder, result)
                case MemberResult():
                    await _record_member(recorder, result)
                case MemberSkippedResult():
                    pass

    except Exception as e:
        log.exception("Error during license file check execution:")
        await recorder.exception("Error during license file check execution", {"error": str(e)})

    return None


async def headers(args: checks.FunctionArguments) -> results.Results | None:
    """Check that all source files have valid license headers."""
    recorder = await args.recorder()
    if not (artifact_abs_path := await recorder.abs_path()):
        return None
    if await recorder.primary_path_is_binary():
        return None

    log.info(f"Checking license headers for {artifact_abs_path} (rel: {args.primary_rel_path})")

    async with db.session() as data:
        release = await data.release(project_name=args.project_name, version=args.version_name).get()
    ignore_lines = []
    if release is not None:
        release_directory_base = util.release_directory_base(release)
        release_directory_revision = release_directory_base / args.revision_number
        ignore_file = release_directory_revision / ".atr" / "license-headers-ignore"
        if ignore_file.exists():
            ignore_lines = ignore_file.read_text().splitlines()

    return await _headers_core(recorder, str(artifact_abs_path), ignore_lines)


def headers_validate(content: bytes, _filename: str) -> tuple[bool, str | None]:
    """Validate that the content contains the Apache License header."""
    generated_by_patterns = [
        b"Generated By:JJTree",
        b"Generated By:JavaCC",
    ]
    for pattern in generated_by_patterns:
        if pattern in content:
            return True, None

    r_span = re.compile(rb"Licensed to the.*?under the License", re.MULTILINE)
    r_words = re.compile(rb"[A-Za-z0-9]+")

    # Normalise the content
    content = re.sub(rb"[ \t\r\n]+", b" ", content)

    # For each matching heuristic span...
    for span in r_span.finditer(content):
        # Get only the words in the span
        words = r_words.findall(span.group(0))
        joined = b" ".join(words).lower()
        if joined == HTTP_APACHE_LICENSE_HEADER.lower():
            return True, None
        elif joined == HTTPS_APACHE_LICENSE_HEADER.lower():
            return True, None
    return False, "Could not find Apache License header"


# File helpers


def _files_check_core_logic(artifact_path: str, is_podling: bool) -> Iterator[Result]:
    """Verify that LICENSE and NOTICE files exist and are placed and formatted correctly."""
    license_results: dict[str, str | None] = {}
    notice_results: dict[str, tuple[bool, list[str], str]] = {}
    disclaimer_found = False

    # Check for license files in the root directory
    with tarzip.open_archive(artifact_path) as archive:
        for member in archive:
            if member.name and member.name.split("/")[-1].startswith("._"):
                # Metadata convention
                continue

            if member.name.count("/") > 1:
                # Skip files in subdirectories
                continue

            filename = os.path.basename(member.name)
            if filename == "LICENSE":
                # TODO: Check length, should be 11,358 bytes
                license_diff = _files_check_core_logic_license(archive, member)
                license_results[filename] = license_diff
            elif filename == "NOTICE":
                # TODO: Check length doesn't exceed some preset
                notice_ok, notice_issues, notice_preamble = _files_check_core_logic_notice(archive, member)
                notice_results[filename] = (notice_ok, notice_issues, notice_preamble)
            elif filename in {"DISCLAIMER", "DISCLAIMER-WIP"}:
                disclaimer_found = True

    yield from _license_results(license_results)
    yield from _notice_results(notice_results)
    if is_podling and (not disclaimer_found):
        yield ArtifactResult(
            status=sql.CheckResultStatus.FAILURE,
            message="No DISCLAIMER or DISCLAIMER-WIP file found",
            data=None,
        )


def _files_check_core_logic_license(archive: tarzip.Archive, member: tarzip.Member) -> str | None:
    """Verify that the start of the LICENSE file matches the Apache 2.0 license."""
    f = archive.extractfile(member)
    if not f:
        return None

    sha3e = hashlib.sha3_256()
    sha3e.update(static.APACHE_LICENSE_2_0.encode("utf-8"))
    sha3_expected = sha3e.hexdigest()

    if sha3_expected != "5efa4839f385df309ffc022ca5ce9763c4bc709dab862ca77d9a894db6598456":
        log.error("SHA3 expected value is incorrect, please update the static.LICENSE constant")

    # It is common for the license to be used without the leading blank line
    apache_license_2_0 = static.APACHE_LICENSE_2_0.removeprefix("\n")
    # Remove the trailing newline for further normalisation
    apache_license_2_0 = apache_license_2_0.removesuffix("\n")
    content = f.read()
    package_license = content.decode("utf-8", errors="replace")
    package_license = package_license.replace("\r\n", "\n")
    package_license = package_license.removeprefix("\n")
    package_license = package_license[: len(apache_license_2_0)]
    if package_license != apache_license_2_0:
        # TODO: Only show a contextual diff, not the full diff
        diff = difflib.ndiff(apache_license_2_0.splitlines(), package_license.splitlines())
        return "\n".join(diff)

    return None


def _files_check_core_logic_notice(archive: tarzip.Archive, member: tarzip.Member) -> tuple[bool, list[str], str]:
    """Verify that the NOTICE file follows the required format."""
    f = archive.extractfile(member)
    if not f:
        return False, ["the NOTICE file is missing or could not be read"], ""

    try:
        content = f.read().decode("utf-8")
    except UnicodeDecodeError:
        return False, ["the NOTICE file is not valid UTF-8"], ""
    preamble = "".join(content.splitlines(keepends=True)[:3])
    issues = []

    if not re.search(r"Apache\s+[\w\-\.]+", content, re.MULTILINE):
        issues.append("missing or invalid Apache product header")
    if not re.search(r"Copyright\s+(?:\d{4}|\d{4}-\d{4})\s+The Apache Software Foundation", content, re.MULTILINE):
        issues.append("missing or invalid copyright statement")
    if not re.search(
        r"This product includes software developed at\s*\nThe Apache Software Foundation \(.*?\)", content, re.DOTALL
    ):
        issues.append("missing or invalid foundation attribution")

    return len(issues) == 0, issues, preamble


def _license_results(
    license_results: dict[str, str | None],
) -> Iterator[Result]:
    """Build status messages for license file verification."""
    license_files_size = len(license_results)
    if license_files_size == 0:
        yield ArtifactResult(
            status=sql.CheckResultStatus.FAILURE,
            message="No LICENSE file found",
            data=None,
        )
        return

    if license_files_size > 1:
        yield ArtifactResult(
            status=sql.CheckResultStatus.FAILURE,
            message="Multiple LICENSE files found",
            data=None,
        )
        return

    for filename, license_diff in license_results.items():
        # Unpack the single result by iterating
        if license_diff is None:
            yield ArtifactResult(
                status=sql.CheckResultStatus.SUCCESS,
                message=f"{filename} is valid",
                data=None,
            )
        else:
            yield ArtifactResult(
                status=sql.CheckResultStatus.FAILURE,
                message=f"{filename} is invalid",
                data={"diff": license_diff},
            )


def _notice_results(
    notice_results: dict[str, tuple[bool, list[str], str]],
) -> Iterator[Result]:
    """Build status messages for notice file verification."""
    notice_files_size = len(notice_results)
    if notice_files_size == 0:
        yield ArtifactResult(
            status=sql.CheckResultStatus.FAILURE,
            message="No NOTICE file found",
            data=None,
        )
        return

    if notice_files_size > 1:
        yield ArtifactResult(
            status=sql.CheckResultStatus.FAILURE,
            message="Multiple NOTICE files found",
            data=None,
        )
        return

    for filename, (notice_ok, notice_issues, notice_preamble) in notice_results.items():
        # Unpack the single result by iterating
        if notice_ok:
            yield ArtifactResult(
                status=sql.CheckResultStatus.SUCCESS,
                message=f"{filename} is valid",
                data=None,
            )
        else:
            yield ArtifactResult(
                status=sql.CheckResultStatus.FAILURE,
                message=f"{filename} is invalid",
                data={"issues": notice_issues, "preamble": notice_preamble},
            )


# Header helpers


def _get_file_extension(filename: str) -> str | None:
    """Get the file extension without the dot."""
    _, ext = os.path.splitext(filename)
    if not ext:
        return None
    return ext[1:].lower()


def _headers_check_core_logic(artifact_path: str, ignore_lines: list[str]) -> Iterator[Result]:
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

    artifact_basename = os.path.basename(artifact_path)
    # log.info(f"Ignore lines: {ignore_lines}")

    # Check files in the archive
    with tarzip.open_archive(artifact_path) as archive:
        for member in archive:
            if member.name and member.name.split("/")[-1].startswith("._"):
                # Metadata convention
                continue

            ignore_path = "/" + artifact_basename + "/" + member.name.lstrip("/")
            matcher = util.create_path_matcher(ignore_lines, pathlib.Path(ignore_path), pathlib.Path("/"))
            # log.info(f"Checking {ignore_path} with matcher {matcher}")
            if matcher(ignore_path):
                # log.info(f"Skipping {ignore_path} because it matches the ignore list")
                continue

            match _headers_check_core_logic_process_file(archive, member):
                case ArtifactResult() | MemberResult() as result:
                    artifact_data.files_checked += 1
                    match result.status:
                        case sql.CheckResultStatus.SUCCESS:
                            artifact_data.files_with_valid_headers += 1
                        case sql.CheckResultStatus.FAILURE:
                            artifact_data.files_with_invalid_headers += 1
                        case sql.CheckResultStatus.WARNING:
                            artifact_data.files_with_invalid_headers += 1
                        case sql.CheckResultStatus.EXCEPTION:
                            artifact_data.files_with_invalid_headers += 1
                    yield result
                case MemberSkippedResult():
                    artifact_data.files_skipped += 1

    yield ArtifactResult(
        status=sql.CheckResultStatus.SUCCESS,
        message=f"Checked {artifact_data.files_checked} files,"
        f" found {artifact_data.files_with_valid_headers} with valid headers,"
        f" {artifact_data.files_with_invalid_headers} with invalid headers,"
        f" and {artifact_data.files_skipped} skipped",
        data=artifact_data.model_dump_json(),
    )


def _headers_check_core_logic_process_file(
    archive: tarzip.Archive,
    member: tarzip.Member,
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
        f = archive.extractfile(member)
        if f is None:
            return MemberResult(
                status=sql.CheckResultStatus.EXCEPTION,
                path=member.name,
                message="Could not read file",
                data=None,
            )

        # Allow for some extra content at the start of the file
        # That may be shebangs, encoding declarations, etc.
        content = f.read(4096)
        is_valid, error = headers_validate(content, member.name)
        if is_valid:
            return MemberResult(
                status=sql.CheckResultStatus.SUCCESS,
                path=member.name,
                message="Valid license header",
                data=None,
            )
        else:
            return MemberResult(
                status=sql.CheckResultStatus.FAILURE,
                path=member.name,
                message=f"Invalid license header: {error}",
                data=None,
            )
    except Exception as e:
        return MemberResult(
            status=sql.CheckResultStatus.EXCEPTION,
            path=member.name,
            message=f"Error processing file: {e!s}",
            data=None,
        )


def _headers_check_core_logic_should_check(filepath: str) -> bool:
    """Determine if a file should be checked for license headers."""
    ext = _get_file_extension(filepath)
    if ext is None:
        return False

    # Then check if the file matches any of our included patterns
    for pattern in INCLUDED_PATTERNS:
        if re.search(pattern, filepath, re.IGNORECASE):
            return True

    return False


async def _headers_core(recorder: checks.Recorder, artifact_abs_path: str, ignore_lines: list[str]) -> None:
    try:
        for result in await asyncio.to_thread(_headers_check_core_logic, str(artifact_abs_path), ignore_lines):
            match result:
                case ArtifactResult():
                    await _record_artifact(recorder, result)
                case MemberResult():
                    await _record_member(recorder, result)
                case MemberSkippedResult():
                    pass
        member_failures = recorder.member_problems.get(sql.CheckResultStatus.FAILURE, 0)
        if member_failures > 0:
            await recorder.failure(
                f"Some files had invalid license headers ({member_failures} failures)",
                None,
            )

    except Exception as e:
        await recorder.exception("Error during license header check execution", {"error": str(e)})

    return None


async def _record_artifact(recorder: checks.Recorder, result: ArtifactResult) -> None:
    match result.status:
        case sql.CheckResultStatus.SUCCESS:
            await recorder.success(result.message, result.data)
        case sql.CheckResultStatus.WARNING:
            await recorder.warning(result.message, result.data)
        case sql.CheckResultStatus.FAILURE:
            await recorder.failure(result.message, result.data)
        case sql.CheckResultStatus.EXCEPTION:
            await recorder.exception(result.message, result.data)


async def _record_member(recorder: checks.Recorder, result: MemberResult) -> None:
    match result.status:
        case sql.CheckResultStatus.SUCCESS:
            await recorder.success(result.message, result.data, member_rel_path=result.path)
        case sql.CheckResultStatus.WARNING:
            await recorder.warning(result.message, result.data, member_rel_path=result.path)
        case sql.CheckResultStatus.FAILURE:
            await recorder.failure(result.message, result.data, member_rel_path=result.path)
        case sql.CheckResultStatus.EXCEPTION:
            await recorder.exception(result.message, result.data, member_rel_path=result.path)
