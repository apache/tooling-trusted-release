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
import tempfile
from typing import Any, Final

import gnupg
import sqlmodel

import atr.db as db
import atr.db.models as models
import atr.tasks.checks as checks

_LOGGER = logging.getLogger(__name__)


async def check(args: checks.FunctionArguments) -> str | None:
    """Check a signature file."""
    recorder = await args.recorder()
    if not (primary_abs_path := await recorder.abs_path()):
        return None

    if not (primary_rel_path := args.primary_rel_path):
        await recorder.failure("Primary relative path is required", {"primary_rel_path": primary_rel_path})
        return None

    artifact_rel_path = primary_rel_path.removesuffix(".asc")
    if not (artifact_abs_path := await recorder.abs_path(artifact_rel_path)):
        return None

    committee_name = args.extra_args.get("committee_name")
    if not isinstance(committee_name, str):
        await recorder.failure("Committee name is required", {"committee_name": committee_name})
        return None

    _LOGGER.info(
        f"Checking signature {primary_abs_path} for {artifact_abs_path}"
        f" using {committee_name} keys (rel: {primary_rel_path})"
    )

    try:
        result_data = await _check_core_logic(
            committee_name=committee_name,
            artifact_path=str(artifact_abs_path),
            signature_path=str(primary_abs_path),
        )
        if result_data.get("error"):
            await recorder.failure(result_data["error"], result_data)
        elif result_data.get("verified"):
            await recorder.success("Signature verified successfully", result_data)
        else:
            # Shouldn't happen
            await recorder.failure("Signature verification failed for unknown reasons", result_data)

    except Exception as e:
        await recorder.failure("Error during signature check execution", {"error": str(e)})

    return None


async def _check_core_logic(committee_name: str, artifact_path: str, signature_path: str) -> dict[str, Any]:
    """Verify a signature file using the committee's public signing keys."""
    _LOGGER.info(f"Attempting to fetch keys for committee_name: '{committee_name}'")
    name = db.validate_instrumented_attribute(models.Committee.name)
    async with db.session() as session:
        statement = (
            sqlmodel.select(models.PublicSigningKey)
            .join(models.KeyLink)
            .join(models.Committee)
            .where(name == committee_name)
        )
        result = await session.execute(statement)
        public_keys = [key.ascii_armored_key for key in result.scalars().all()]

    return await asyncio.to_thread(
        _check_core_logic_verify_signature,
        signature_path=signature_path,
        artifact_path=artifact_path,
        ascii_armored_keys=public_keys,
    )


def _check_core_logic_verify_signature(
    signature_path: str, artifact_path: str, ascii_armored_keys: list[str]
) -> dict[str, Any]:
    """Verify a GPG signature for a file."""
    with tempfile.TemporaryDirectory(prefix="gpg-") as gpg_dir, open(signature_path, "rb") as sig_file:
        gpg: Final[gnupg.GPG] = gnupg.GPG(gnupghome=gpg_dir)

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
        return {
            "verified": False,
            "error": "No valid signature found",
            "debug_info": debug_info,
        }

    return {
        "verified": True,
        "key_id": verified.key_id,
        "timestamp": verified.timestamp,
        "username": verified.username or "Unknown",
        "fingerprint": verified.pubkey_fingerprint.lower() or "Unknown",
        "status": "Valid signature",
        "debug_info": debug_info,
    }
