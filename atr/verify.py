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
import os
import re
import shutil
import tarfile
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any, BinaryIO, cast

import gnupg
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.sql import select

from atr.db.models import PMC, PMCKeyLink, PublicSigningKey

# Configure logging
log_format = "[%(asctime)s.%(msecs)03d] [%(process)d] [%(levelname)s] %(message)s"
date_format = "%Y-%m-%d %H:%M:%S"
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler("atr-worker.log")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
logger.addHandler(file_handler)


class VerifyError(Exception):
    """Error during verification."""

    def __init__(self, message: str, *result: Any) -> None:
        self.message = message
        self.result = tuple(result)


def db_session_get() -> Session:
    """Get a new database session."""
    # Create database engine
    engine = create_engine("sqlite:///atr.db", echo=False)
    return Session(engine)


def utility_archive_root_dir_find(artifact_path: str) -> tuple[str | None, str | None]:
    """Find the root directory in a tar archive and validate that it has only one root dir."""
    root_dir = None
    error_msg = None

    with tarfile.open(artifact_path, mode="r|gz") as tf:
        for member in tf:
            parts = member.name.split("/", 1)
            if len(parts) >= 1:
                if not root_dir:
                    root_dir = parts[0]
                elif parts[0] != root_dir:
                    error_msg = f"Multiple root directories found: {root_dir}, {parts[0]}"
                    break

    if not root_dir:
        error_msg = "No root directory found in archive"

    return root_dir, error_msg


def archive_integrity(path: str, chunk_size: int = 4096) -> int:
    """Verify a .tar.gz file and compute its uncompressed size."""
    total_size = 0

    with tarfile.open(path, mode="r|gz") as tf:
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


def archive_structure(path: str, filename: str) -> dict[str, Any]:
    """
    Verify that the archive contains exactly one root directory named after the package.
    The package name should match the archive filename without the .tar.gz extension.
    """
    expected_dirname = os.path.splitext(os.path.splitext(filename)[0])[0]
    root_dirs = set()

    with tarfile.open(path, mode="r|gz") as tf:
        for member in tf:
            parts = member.name.split("/", 1)
            if len(parts) >= 1:
                root_dirs.add(parts[0])

    if len(root_dirs) == 0:
        return {"valid": False, "root_dirs": list(root_dirs), "message": "Archive contains no directories"}
    elif len(root_dirs) > 1:
        return {
            "valid": False,
            "root_dirs": list(root_dirs),
            "message": f"Archive contains multiple root directories: {', '.join(root_dirs)}",
        }

    root_dir = root_dirs.pop()
    if root_dir != expected_dirname:
        return {
            "valid": False,
            "root_dirs": [root_dir],
            "message": f"Root directory '{root_dir}' does not match expected name '{expected_dirname}'",
        }

    return {"valid": True, "root_dirs": [root_dir], "message": "Archive structure is valid"}


def license_files_license(tf: tarfile.TarFile, member: tarfile.TarInfo) -> bool:
    """Verify that the LICENSE file matches the Apache 2.0 license."""
    import hashlib

    f = tf.extractfile(member)
    if not f:
        return False

    sha3 = hashlib.sha3_256()
    content = f.read()
    sha3.update(content)
    return sha3.hexdigest() == "8a0a8fb6c73ef27e4322391c7b28e5b38639e64e58c40a2c7a51cec6e7915a6a"


def license_files_messages_build(
    root_dir: str,
    files_found: list[str],
    license_ok: bool,
    notice_ok: bool,
    notice_issues: list[str],
) -> list[str]:
    """Build status messages for license file verification."""
    messages = []
    if not files_found:
        messages.append(f"No LICENSE or NOTICE files found in root directory '{root_dir}'")
    else:
        if "LICENSE" not in files_found:
            messages.append(f"LICENSE file not found in root directory '{root_dir}'")
        elif not license_ok:
            messages.append("LICENSE file does not match Apache 2.0 license")

        if "NOTICE" not in files_found:
            messages.append(f"NOTICE file not found in root directory '{root_dir}'")
        elif not notice_ok:
            messages.append("NOTICE file format issues: " + "; ".join(notice_issues))

    return messages


def license_files_notice(tf: tarfile.TarFile, member: tarfile.TarInfo) -> tuple[bool, list[str]]:
    """Verify that the NOTICE file follows the required format."""
    import re

    f = tf.extractfile(member)
    if not f:
        return False, ["Could not read NOTICE file"]

    content = f.read().decode("utf-8")
    issues = []

    if not re.search(r"Apache\s+[\w\-\.]+", content, re.MULTILINE):
        issues.append("Missing or invalid Apache product header")
    if not re.search(r"Copyright\s+(?:\d{4}|\d{4}-\d{4})\s+The Apache Software Foundation", content, re.MULTILINE):
        issues.append("Missing or invalid copyright statement")
    if not re.search(
        r"This product includes software developed at\s*\nThe Apache Software Foundation \(.*?\)", content, re.DOTALL
    ):
        issues.append("Missing or invalid foundation attribution")

    return len(issues) == 0, issues


def license_files(artifact_path: str) -> dict[str, Any]:
    """Verify that LICENSE and NOTICE files exist and are placed and formatted correctly."""
    files_found = []
    license_ok = False
    notice_ok = False
    notice_issues: list[str] = []

    # First find and validate the root directory
    root_dir, error_msg = utility_archive_root_dir_find(artifact_path)
    if error_msg or root_dir is None:
        return {
            "files_checked": ["LICENSE", "NOTICE"],
            "files_found": [],
            "license_valid": False,
            "notice_valid": False,
            "message": error_msg or "No root directory found",
        }

    # Check for license files in the root directory
    with tarfile.open(artifact_path, mode="r|gz") as tf:
        for member in tf:
            if member.name in [f"{root_dir}/LICENSE", f"{root_dir}/NOTICE"]:
                filename = os.path.basename(member.name)
                files_found.append(filename)
                if filename == "LICENSE":
                    # TODO: Check length, should be 11,358 bytes
                    license_ok = license_files_license(tf, member)
                elif filename == "NOTICE":
                    # TODO: Check length doesn't exceed some preset
                    notice_ok, notice_issues = license_files_notice(tf, member)

    messages = license_files_messages_build(root_dir, files_found, license_ok, notice_ok, notice_issues)

    return {
        "files_checked": ["LICENSE", "NOTICE"],
        "files_found": files_found,
        "license_valid": license_ok,
        "notice_valid": notice_ok,
        "notice_issues": notice_issues if notice_issues else None,
        "message": "; ".join(messages) if messages else "All license files present and valid",
    }


def signature(pmc_name: str, artifact_path: str, signature_path: str) -> dict[str, Any]:
    """Verify a signature file using the PMC's public signing keys."""
    # Query only the signing keys associated with this PMC
    with db_session_get() as session:
        from sqlalchemy.sql.expression import ColumnElement

        statement = (
            select(PublicSigningKey)
            .join(PMCKeyLink)
            .join(PMC)
            .where(cast(ColumnElement[bool], PMC.project_name == pmc_name))
        )
        result = session.execute(statement)
        public_keys = [key.ascii_armored_key for key in result.scalars().all()]

    with open(signature_path, "rb") as sig_file:
        return signature_gpg_file(sig_file, artifact_path, public_keys)


def signature_gpg_file(sig_file: BinaryIO, artifact_path: str, ascii_armored_keys: list[str]) -> dict[str, Any]:
    """Verify a GPG signature for a file."""

    @contextmanager
    def ephemeral_gpg_home() -> Generator[str]:
        """Create a temporary directory for an isolated GPG home, and clean it up on exit."""
        temp_dir = tempfile.mkdtemp(prefix="gpg-")
        try:
            yield temp_dir
        finally:
            shutil.rmtree(temp_dir)

    with ephemeral_gpg_home() as gpg_home:
        gpg = gnupg.GPG(gnupghome=gpg_home)

        # Import all PMC public signing keys
        for key in ascii_armored_keys:
            import_result = gpg.import_keys(key)
            if not import_result.fingerprints:
                # TODO: Log warning about invalid key?
                continue
        verified = gpg.verify_file(sig_file, str(artifact_path))

    # Collect all available information for debugging
    debug_info = {
        "key_id": verified.key_id or "Not available",
        "fingerprint": verified.fingerprint.lower() if verified.fingerprint else "Not available",
        "pubkey_fingerprint": verified.pubkey_fingerprint.lower() if verified.pubkey_fingerprint else "Not available",
        "creation_date": verified.creation_date or "Not available",
        "timestamp": verified.timestamp or "Not available",
        "username": verified.username or "Not available",
        "status": verified.status or "Not available",
        "valid": bool(verified),
        "trust_level": verified.trust_level if hasattr(verified, "trust_level") else "Not available",
        "trust_text": verified.trust_text if hasattr(verified, "trust_text") else "Not available",
        "stderr": verified.stderr if hasattr(verified, "stderr") else "Not available",
        "num_pmc_keys": len(ascii_armored_keys),
    }

    if not verified:
        raise VerifyError("No valid signature found", debug_info)

    return {
        "verified": True,
        "key_id": verified.key_id,
        "timestamp": verified.timestamp,
        "username": verified.username or "Unknown",
        "email": verified.pubkey_fingerprint.lower() or "Unknown",
        "status": "Valid signature",
        "debug_info": debug_info,
    }


# File type comment style definitions
# Ordered by their popularity in the Stack Overflow Developer Survey 2024
COMMENT_STYLES = {
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
INCLUDED_PATTERNS = [
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

# Constant that must be present in the Apache License header
APACHE_LICENSE_HEADER = b"""\
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


def license_header_strip_comments(content: bytes, file_ext: str) -> bytes:
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


def license_header_validate(content: bytes, filename: str) -> tuple[bool, str | None]:
    """Validate that the content contains the Apache License header after removing comments."""
    # Get the file extension from the filename
    file_ext = license_header_file_type_get(filename)
    if not file_ext or file_ext not in COMMENT_STYLES:
        return False, "Could not determine file type from extension"

    # Strip comments, removing empty lines in the process
    cleaned_header = license_header_strip_comments(content, file_ext)

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
        #         logger.debug("\nFirst difference at line %d:", i + 1)
        #         logger.debug("Expected: '%s'", e.decode(errors="replace"))
        #         logger.debug("Got:      '%s'", c.decode(errors="replace"))
        #         break
        return False, "License header does not match the required Apache License header text"

    return True, None


def license_header_file_should_check(filepath: str) -> bool:
    """Determine if a file should be checked for license headers."""
    ext = license_header_file_type_get(filepath)
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


def license_header_file_type_get(filename: str) -> str | None:
    """Get the file extension without the dot."""
    _, ext = os.path.splitext(filename)
    if not ext:
        return None
    return ext[1:].lower()


def license_header_file_process(
    tf: tarfile.TarFile,
    member: tarfile.TarInfo,
    root_dir: str,
) -> tuple[bool, dict[str, Any]]:
    """Process a single file in an archive for license header verification."""
    if not member.isfile():
        return False, {}

    # Check if we should verify this file, based on extension
    if not license_header_file_should_check(member.name):
        return False, {}

    # Get relative path for display purposes only
    display_path = member.name
    if display_path.startswith(f"{root_dir}/"):
        display_path = display_path[len(root_dir) + 1 :]

    # Extract and check the file
    try:
        f = tf.extractfile(member)
        if f is None:
            return True, {"error": f"Could not read file: {display_path}"}

        # Allow for some extra content at the start of the file
        # That may be shebangs, encoding declarations, etc.
        content = f.read(len(APACHE_LICENSE_HEADER) * 2)
        is_valid, error = license_header_validate(content, member.name)
        if is_valid:
            return True, {"valid": True}
        else:
            return True, {"valid": False, "error": f"{display_path}: {error}"}
    except Exception as e:
        return True, {"error": f"Error processing {display_path}: {e!s}"}


def license_header_verify(artifact_path: str) -> dict[str, Any]:
    """Verify Apache License headers in source files within an archive."""
    # We could modify @Lucas-C/pre-commit-hooks instead for this
    # But hopefully this will be robust enough, at least for testing
    files_checked = 0
    files_with_valid_headers = 0
    errors = []

    # First find and validate the root directory
    root_dir, error_msg = utility_archive_root_dir_find(artifact_path)
    if error_msg or (root_dir is None):
        return {
            "files_checked": 0,
            "files_with_valid_headers": 0,
            "errors": [error_msg or "No root directory found"],
            "message": error_msg or "No root directory found",
            "valid": False,
        }

    # Check files in the archive
    with tarfile.open(artifact_path, mode="r|gz") as tf:
        for member in tf:
            processed, result = license_header_file_process(tf, member, root_dir)
            if not processed:
                continue

            files_checked += 1
            if result.get("error"):
                errors.append(result["error"])
            elif result.get("valid"):
                files_with_valid_headers += 1
            else:
                # Should be impossible
                raise RuntimeError("Logic error")

    # Prepare result message
    if files_checked == 0:
        message = "No source files found to check for license headers"
        # No files to check is not a failure
        valid = True
    else:
        # Require all files to have valid headers
        valid = files_checked == files_with_valid_headers
        message = f"Checked {files_checked} files, found {files_with_valid_headers} with valid headers"

    return {
        "files_checked": files_checked,
        "files_with_valid_headers": files_with_valid_headers,
        "errors": errors,
        "message": message,
        "valid": valid,
    }
