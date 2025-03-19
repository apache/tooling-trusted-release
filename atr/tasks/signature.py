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

import contextlib
import logging
import shutil
import tempfile
from collections.abc import Generator
from typing import Any, BinaryIO, Final

import gnupg
import sqlalchemy.sql as sql

import atr.db as db
import atr.db.models as models
import atr.tasks.task as task

_LOGGER = logging.getLogger(__name__)


def check(args: list[str]) -> tuple[models.TaskStatus, str | None, tuple[Any, ...]]:
    """Check a signature file."""
    task_results = task.results_as_tuple(_check_core(*args))
    _LOGGER.info(f"Verified {args} with result {task_results[0]}")
    status = task.FAILED if task_results[0].get("error") else task.COMPLETED
    error = task_results[0].get("error")
    return status, error, task_results


def _check_core(committee_name: str, artifact_path: str, signature_path: str) -> dict[str, Any]:
    """Verify a signature file using the committee's public signing keys."""
    # Query only the signing keys associated with this committee
    # TODO: Rename create_sync_db_session to create_session_sync
    # Using isinstance does not work here, with pyright
    name = db.validate_instrumented_attribute(models.Committee.name)
    with db.create_sync_db_session() as session:
        # TODO: This is our only remaining use of select
        statement = (
            sql.select(models.PublicSigningKey)
            .join(models.KeyLink)
            .join(models.Committee)
            .where(name == committee_name)
        )
        result = session.execute(statement)
        public_keys = [key.ascii_armored_key for key in result.scalars().all()]

    with open(signature_path, "rb") as sig_file:
        return _signature_gpg_file(sig_file, artifact_path, public_keys)


@contextlib.contextmanager
def _ephemeral_gpg_home() -> Generator[str]:
    # TODO: Deduplicate, and move somewhere more appropriate
    """Create a temporary directory for an isolated GPG home, and clean it up on exit."""
    temp_dir = tempfile.mkdtemp(prefix="gpg-")
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir)


def _signature_gpg_file(sig_file: BinaryIO, artifact_path: str, ascii_armored_keys: list[str]) -> dict[str, Any]:
    """Verify a GPG signature for a file."""
    with _ephemeral_gpg_home() as gpg_home:
        gpg: Final[gnupg.GPG] = gnupg.GPG(gnupghome=gpg_home)

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
        "num_committee_keys": len(ascii_armored_keys),
    }

    if not verified:
        raise task.Error("No valid signature found", debug_info)

    return {
        "verified": True,
        "key_id": verified.key_id,
        "timestamp": verified.timestamp,
        "username": verified.username or "Unknown",
        "email": verified.pubkey_fingerprint.lower() or "Unknown",
        "status": "Valid signature",
        "debug_info": debug_info,
    }
