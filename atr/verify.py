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

import os
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
