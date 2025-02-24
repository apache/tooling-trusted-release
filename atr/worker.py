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

"""worker.py - Task worker process for ATR"""

# TODO: If started is older than some threshold and status
# is active but the pid is no longer running, we can revert
# the task to status='QUEUED'. For this to work, ideally we
# need to check wall clock time as well as CPU time.

import datetime
import json
import logging
import os
import resource
import shutil
import signal
import sys
import tarfile
import tempfile
import time
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC
from typing import Any, BinaryIO, cast

import gnupg
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.sql import select

from atr.db.models import PMC, PMCKeyLink, PublicSigningKey

# Configure logging
logging.basicConfig(
    format="[%(asctime)s.%(msecs)03d] [%(process)d] [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Resource limits, 5 minutes and 1GB
CPU_LIMIT_SECONDS = 300
MEMORY_LIMIT_BYTES = 1024 * 1024 * 1024

# # Create tables if they don't exist
# SQLModel.metadata.create_all(engine)


class VerifyError(Exception):
    """Error during verification."""

    def __init__(self, message: str, *result: Any) -> None:
        self.message = message
        self.result = tuple(result)


def verify_archive_integrity(path: str, chunk_size: int = 4096) -> int:
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


def verify_signature(pmc_name: str, artifact_path: str, signature_path: str) -> dict[str, Any]:
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
        return verify_signature_gpg_file(sig_file, artifact_path, public_keys)


def verify_signature_gpg_file(sig_file: BinaryIO, artifact_path: str, ascii_armored_keys: list[str]) -> dict[str, Any]:
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


def verify_license_files_license(tf: tarfile.TarFile, member: tarfile.TarInfo) -> bool:
    """Verify that the LICENSE file matches the Apache 2.0 license."""
    import hashlib

    f = tf.extractfile(member)
    if not f:
        return False

    sha3 = hashlib.sha3_256()
    content = f.read()
    sha3.update(content)
    return sha3.hexdigest() == "8a0a8fb6c73ef27e4322391c7b28e5b38639e64e58c40a2c7a51cec6e7915a6a"


def verify_license_files_notice(tf: tarfile.TarFile, member: tarfile.TarInfo) -> tuple[bool, list[str]]:
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


def verify_archive_structure(path: str, filename: str) -> dict[str, Any]:
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


def find_archive_root_dir(artifact_path: str) -> tuple[str | None, str | None]:
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


def verify_license_files_messages_build(
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


def verify_license_files(artifact_path: str) -> dict[str, Any]:
    """Verify that LICENSE and NOTICE files exist and are placed and formatted correctly."""
    files_found = []
    license_ok = False
    notice_ok = False
    notice_issues: list[str] = []

    # First find and validate the root directory
    root_dir, error_msg = find_archive_root_dir(artifact_path)
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
                    license_ok = verify_license_files_license(tf, member)
                elif filename == "NOTICE":
                    # TODO: Check length doesn't exceed some preset
                    notice_ok, notice_issues = verify_license_files_notice(tf, member)

    messages = verify_license_files_messages_build(root_dir, files_found, license_ok, notice_ok, notice_issues)

    return {
        "files_checked": ["LICENSE", "NOTICE"],
        "files_found": files_found,
        "license_valid": license_ok,
        "notice_valid": notice_ok,
        "notice_issues": notice_issues if notice_issues else None,
        "message": "; ".join(messages) if messages else "All license files present and valid",
    }


def db_session_get() -> Session:
    """Get a new database session."""
    # Create database engine
    engine = create_engine("sqlite:///atr.db", echo=False)
    return Session(engine)


def task_next_claim() -> tuple[int, str, str] | None:
    """
    Attempt to claim the oldest unclaimed task.
    Returns (task_id, task_type, task_args) if successful.
    Returns None if no tasks are available.
    """
    with db_session_get() as session:
        with session.begin():
            # Find and claim the oldest unclaimed task
            # We have an index on (status, added)
            result = session.execute(
                text("""
                    UPDATE task
                    SET started = :now, pid = :pid, status = 'ACTIVE'
                    WHERE id = (
                        SELECT id FROM task
                        WHERE status = 'QUEUED'
                        ORDER BY added ASC LIMIT 1
                    )
                    AND status = 'QUEUED'
                    RETURNING id, task_type, task_args
                    """),
                {"now": datetime.datetime.now(UTC), "pid": os.getpid()},
            )
            task = result.first()
            if task:
                task_id, task_type, task_args = task
                logger.info(f"Claimed task {task_id} ({task_type}) with args {task_args}")
                return task_id, task_type, task_args

            return None


def wrap(item: Any) -> tuple[Any, ...]:
    """Ensure that returned results are structured as a tuple."""
    if not isinstance(item, tuple):
        return (item,)
    return item


def task_result_process(
    task_id: int, task_results: tuple[Any, ...], status: str = "COMPLETED", error: str | None = None
) -> None:
    """Process and store task results in the database."""
    with db_session_get() as session:
        result = json.dumps(task_results)
        with session.begin():
            if status == "FAILED" and error:
                session.execute(
                    text("""
                        UPDATE task
                        SET status = :status, completed = :now, result = :result, error = :error
                        WHERE id = :task_id
                        """),
                    {
                        "now": datetime.datetime.now(UTC),
                        "task_id": task_id,
                        "result": result,
                        "status": status,
                        "error": error,
                    },
                )
            else:
                session.execute(
                    text("""
                        UPDATE task
                        SET status = :status, completed = :now, result = :result
                        WHERE id = :task_id
                        """),
                    {"now": datetime.datetime.now(UTC), "task_id": task_id, "result": result, "status": status},
                )


def task_error_handle(task_id: int, e: Exception) -> None:
    """Handle task error by updating the database with error information."""
    if isinstance(e, VerifyError):
        logger.error(f"Task {task_id} failed: {e.message}")
        result = json.dumps(e.result)
        with db_session_get() as session:
            with session.begin():
                session.execute(
                    text("""
                        UPDATE task
                        SET status = 'FAILED', completed = :now, error = :error, result = :result
                        WHERE id = :task_id
                        """),
                    {"now": datetime.datetime.now(UTC), "task_id": task_id, "error": e.message, "result": result},
                )
    else:
        logger.error(f"Task {task_id} failed: {e}")
        with db_session_get() as session:
            with session.begin():
                session.execute(
                    text("""
                        UPDATE task
                        SET status = 'FAILED', completed = :now, error = :error
                        WHERE id = :task_id
                        """),
                    {"now": datetime.datetime.now(UTC), "task_id": task_id, "error": str(e)},
                )


def task_process(task_id: int, task_type: str, task_args: str) -> None:
    """Process a claimed task."""
    logger.info(f"Processing task {task_id} ({task_type}) with args {task_args}")
    try:
        status = "COMPLETED"
        error = None
        args = json.loads(task_args)

        if task_type == "verify_archive_integrity":
            task_results = wrap(verify_archive_integrity(*args))
            logger.info(f"Verified {args} and computed size {task_results[0]}")
        elif task_type == "verify_signature":
            task_results = wrap(verify_signature(*args))
            logger.info(f"Verified {args} with result {task_results[0]}")
            if task_results[0]["error"]:
                status = "FAILED"
        elif task_type == "verify_archive_structure":
            task_results = wrap(verify_archive_structure(*args))
            logger.info(f"Verified archive structure for {args}")
            if not task_results[0]["valid"]:
                status = "FAILED"
                error = task_results[0]["message"]
        elif task_type == "verify_license_files":
            task_results = wrap(verify_license_files(*args))
            logger.info(f"Verified license files for {args}")
            if not task_results[0]["files_found"]:
                status = "FAILED"
                error = "Required license files not found"
        else:
            error = f"Unknown task type: {task_type}"
            logger.error(error)
            raise Exception(error)

        task_result_process(task_id, task_results, status, error)

    except Exception as e:
        task_error_handle(task_id, e)


def worker_resources_limit_set() -> None:
    """Set CPU and memory limits for this process."""
    # # Set CPU time limit
    # try:
    #     resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_SECONDS, CPU_LIMIT_SECONDS))
    #     logger.info(f"Set CPU time limit to {CPU_LIMIT_SECONDS} seconds")
    # except ValueError as e:
    #     logger.warning(f"Could not set CPU time limit: {e}")

    # Set memory limit
    try:
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT_BYTES, MEMORY_LIMIT_BYTES))
        logger.info(f"Set memory limit to {MEMORY_LIMIT_BYTES} bytes")
    except ValueError as e:
        logger.warning(f"Could not set memory limit: {e}")


def worker_loop_run() -> None:
    """Main worker loop."""
    if os.path.isdir("state"):
        os.chdir("state")

    while True:
        try:
            task = task_next_claim()
            if task:
                task_id, task_type, task_args = task
                task_process(task_id, task_type, task_args)
                # Only process one task and then exit
                # This prevents memory leaks from accumulating
                break
            else:
                # No tasks available, wait 20ms before checking again
                time.sleep(0.02)
        except Exception as e:
            # TODO: Should probably be more robust about this
            logger.error(f"Worker loop error: {e}")
            time.sleep(1)


def worker_signal_handle(signum: int, frame: object) -> None:
    """Handle termination signals gracefully."""
    # For RLIMIT_AS we'll generally get a SIGKILL
    # For RLIMIT_CPU we'll get a SIGXCPU, which we can catch
    logger.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)


def main() -> None:
    """Main entry point."""
    signal.signal(signal.SIGTERM, worker_signal_handle)
    signal.signal(signal.SIGINT, worker_signal_handle)

    worker_resources_limit_set()
    worker_loop_run()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        with open("atr-worker-error.log", "a") as f:
            f.write(f"{datetime.datetime.now(UTC)}: {e}\n")
            f.flush()
