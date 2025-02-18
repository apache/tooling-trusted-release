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

"""routes.py"""

import asyncio
import datetime
import hashlib
import pprint
import secrets
import shutil
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, BinaryIO, cast

import aiofiles
import aiofiles.os
import gnupg
from quart import Request, render_template, request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlmodel import select
from werkzeug.datastructures import FileStorage

from asfquart import APP
from asfquart.auth import Requirements, require
from asfquart.base import ASFQuartException
from asfquart.session import ClientSession
from asfquart.session import read as session_read
from atr.db.models import (
    PMC,
    Package,
    PMCKeyLink,
    PublicSigningKey,
    Release,
    ReleasePhase,
    ReleaseStage,
)

from .db import get_session
from .db.service import get_pmc_by_name, get_pmcs
from .util import compute_sha512, get_release_storage_dir

if APP is ...:
    raise ValueError("APP is not set")

# |         1 | RSA (Encrypt or Sign) [HAC]                        |
# |         2 | RSA Encrypt-Only [HAC]                             |
# |         3 | RSA Sign-Only [HAC]                                |
# |        16 | Elgamal (Encrypt-Only) [ELGAMAL] [HAC]             |
# |        17 | DSA (Digital Signature Algorithm) [FIPS186] [HAC]  |
# |        18 | ECDH public key algorithm                          |
# |        19 | ECDSA public key algorithm [FIPS186]               |
# |        20 | Reserved (formerly Elgamal Encrypt or Sign)        |
# |        21 | Reserved for Diffie-Hellman                        |
# |           | (X9.42, as defined for IETF-S/MIME)                |
# |        22 | EdDSA [I-D.irtf-cfrg-eddsa]                        |
# - https://lists.gnupg.org/pipermail/gnupg-devel/2017-April/032762.html
# TODO: (Obviously we should move this, but where to?)
algorithms = {
    1: "RSA",
    2: "RSA",
    3: "RSA",
    16: "Elgamal",
    17: "DSA",
    18: "ECDH",
    19: "ECDSA",
    21: "Diffie-Hellman",
    22: "EdDSA",
}


@APP.route("/")
async def root() -> str:
    """Main page."""
    return await render_template("index.html")


@APP.route("/pages")
async def root_pages() -> str:
    """List all pages on the website."""
    return await render_template("pages.html")


async def add_release_candidate_post(session: ClientSession, request: Request) -> str:
    form = await request.form

    project_name = form.get("project_name")
    if not project_name:
        raise ASFQuartException("Project name is required", errorcode=400)

    # Verify user is a PMC member of the project
    if project_name not in session.committees:
        raise ASFQuartException(
            f"You must be a PMC member of {project_name} to submit a release candidate", errorcode=403
        )

    # Get all uploaded files
    files = await request.files

    # Get the release artifact and signature files
    artifact_file = files.get("release_artifact")
    signature_file = files.get("release_signature")

    if not artifact_file:
        raise ASFQuartException("Release artifact file is required", errorcode=400)
    if not signature_file:
        raise ASFQuartException("Detached GPG signature file is required", errorcode=400)
    if not signature_file.filename.endswith(".asc"):
        # TODO: Could also check that it's artifact name + ".asc"
        # And at least warn if it's not
        raise ASFQuartException("Signature file must have .asc extension", errorcode=400)

    # Save files using their hashes as filenames
    uploads_path = Path(get_release_storage_dir())
    artifact_hash = await save_file_by_hash(uploads_path, artifact_file)
    # TODO: Do we need to do anything with the signature hash?
    # These should be identical, but path might be absolute?
    # TODO: Need to check, ideally. Could have a data browser
    signature_hash = await save_file_by_hash(uploads_path, signature_file)

    # Generate a 128-bit random token for the release storage key
    storage_token = secrets.token_hex(16)

    # Compute SHA-512 checksum of the artifact for the package record
    checksum_512 = compute_sha512(uploads_path / artifact_hash)

    # Store in database
    async with get_session() as db_session:
        async with db_session.begin():
            # Get PMC
            statement = select(PMC).where(PMC.project_name == project_name)
            pmc = (await db_session.execute(statement)).scalar_one_or_none()
            if not pmc:
                raise ASFQuartException("PMC not found", errorcode=404)

            # Create release record using random token as storage key
            # TODO: Extract version from filename or add to form
            release = Release(
                storage_key=storage_token,
                stage=ReleaseStage.CANDIDATE,
                phase=ReleasePhase.RELEASE_CANDIDATE,
                pmc_id=pmc.id,
                version="TODO",
            )
            db_session.add(release)

            # Create package record
            package = Package(
                file=artifact_hash,
                signature=signature_hash,
                checksum=checksum_512,
                release_key=release.storage_key,
            )
            db_session.add(package)

        return f"Successfully uploaded release candidate for {project_name}"


@asynccontextmanager
async def ephemeral_gpg_home():
    """
    Create a temporary directory for an isolated GnuPG home, and clean it up on exit.
    This is done asynchronously to avoid blocking the event loop.
    """
    # Create a temporary directory off-thread.
    temp_dir = await asyncio.to_thread(tempfile.mkdtemp, prefix="gnupg-")
    try:
        yield temp_dir
    finally:
        # Remove the directory off-thread as well.
        await asyncio.to_thread(shutil.rmtree, temp_dir)


@APP.route("/add-release-candidate", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_add_release_candidate() -> str:
    """Add a release candidate to the database."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    # For POST requests, handle the file upload
    if request.method == "POST":
        return await add_release_candidate_post(session, request)

    # For GET requests, show the form
    return await render_template(
        "add-release-candidate.html",
        asf_id=session.uid,
        pmc_memberships=session.committees,
        committer_projects=session.projects,
    )


@APP.route("/release/signatures/verify/<release_key>")
@require(Requirements.committer)
async def root_release_signatures_verify(release_key: str) -> str:
    """Verify the GPG signatures for all packages in a release candidate."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    async with get_session() as db_session:
        # Get the release and its packages, and PMC with its keys
        release_packages = selectinload(cast(InstrumentedAttribute[list[Package]], Release.packages))
        release_pmc = selectinload(cast(InstrumentedAttribute[PMC], Release.pmc))
        pmc_keys_loader = selectinload(cast(InstrumentedAttribute[PMC], Release.pmc)).selectinload(
            cast(InstrumentedAttribute[list[PublicSigningKey]], PMC.public_signing_keys)
        )

        # For now, for debugging, we'll just get all keys in the database
        statement = select(PublicSigningKey)
        all_signing_keys = (await db_session.execute(statement)).scalars().all()

        statement = (
            select(Release)
            .options(release_packages, release_pmc, pmc_keys_loader)
            .where(Release.storage_key == release_key)
        )
        release = (await db_session.execute(statement)).scalar_one_or_none()
        if not release:
            raise ASFQuartException("Release not found", errorcode=404)

        # Get all ASCII-armored keys associated with the PMC
        ascii_armored_keys = [key.ascii_armored_key for key in all_signing_keys]

        # Verify each package's signature
        verification_results = []
        storage_dir = Path(get_release_storage_dir())

        for package in release.packages:
            result = {"file": package.file}

            artifact_path = storage_dir / package.file
            signature_path = storage_dir / package.signature

            if not artifact_path.exists():
                result["error"] = "Package artifact file not found"
            elif not signature_path.exists():
                result["error"] = "Package signature file not found"
            else:
                # Verify the signature
                result = await verify_gpg_signature(artifact_path, signature_path, ascii_armored_keys)
                result["file"] = package.file

            verification_results.append(result)

        return await render_template(
            "release-signature-verify.html", release=release, verification_results=verification_results
        )


@APP.route("/pmc/<project_name>")
async def root_pmc_arg(project_name: str) -> dict:
    """Get a specific PMC by project name."""
    pmc = await get_pmc_by_name(project_name)
    if not pmc:
        raise ASFQuartException("PMC not found", errorcode=404)

    return {
        "id": pmc.id,
        "project_name": pmc.project_name,
        "pmc_members": pmc.pmc_members,
        "committers": pmc.committers,
        "release_managers": pmc.release_managers,
    }


# @APP.route("/pmc/create/<project_name>")
# async def root_pmc_create_arg(project_name: str) -> dict:
#     "Create a new PMC with some sample data."
#     pmc = PMC(
#         project_name=project_name,
#         pmc_members=["alice", "bob"],
#         committers=["charlie", "dave"],
#         release_managers=["alice"],
#     )

#     async with get_session() as db_session:
#         async with db_session.begin():
#             try:
#                 db_session.add(pmc)
#             except IntegrityError:
#                 raise ASFQuartException(
#                     f"PMC with name '{project_name}' already exists",
#                     errorcode=409,  # HTTP 409 Conflict
#                 )

#         # Convert to dict for response
#         return {
#             "id": pmc.id,
#             "project_name": pmc.project_name,
#             "pmc_members": pmc.pmc_members,
#             "committers": pmc.committers,
#             "release_managers": pmc.release_managers,
#         }


@APP.route("/pmc/directory")
async def root_pmc_directory() -> str:
    """Main PMC directory page."""
    pmcs = await get_pmcs()
    return await render_template("pmc-directory.html", pmcs=pmcs)


@APP.route("/pmc/list")
async def root_pmc_list() -> list[dict]:
    """List all PMCs in the database."""
    pmcs = await get_pmcs()

    return [
        {
            "id": pmc.id,
            "project_name": pmc.project_name,
            "pmc_members": pmc.pmc_members,
            "committers": pmc.committers,
            "release_managers": pmc.release_managers,
        }
        for pmc in pmcs
    ]


@APP.route("/user/keys/add", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_user_keys_add() -> str:
    """Add a new GPG key to the user's account."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    error = None
    key_info = None
    user_keys = []

    # Get all existing keys for the user
    async with get_session() as db_session:
        pmcs_loader = selectinload(cast(InstrumentedAttribute[list[PMC]], PublicSigningKey.pmcs))
        statement = select(PublicSigningKey).options(pmcs_loader).where(PublicSigningKey.apache_uid == session.uid)
        user_keys = (await db_session.execute(statement)).scalars().all()

    if request.method == "POST":
        form = await request.form
        public_key = form.get("public_key")
        if not public_key:
            # Shouldn't happen, so we can raise an exception
            raise ASFQuartException("Public key is required", errorcode=400)

        # Get selected PMCs from form
        selected_pmcs = form.getlist("selected_pmcs")
        if not selected_pmcs:
            return await render_template(
                "user-keys-add.html",
                asf_id=session.uid,
                pmc_memberships=session.committees,
                error="You must select at least one PMC",
                key_info=None,
                user_keys=user_keys,
                algorithms=algorithms,
            )

        # Ensure that the selected PMCs are ones of which the user is actually a member
        invalid_pmcs = [pmc for pmc in selected_pmcs if pmc not in session.committees]
        if invalid_pmcs:
            return await render_template(
                "user-keys-add.html",
                asf_id=session.uid,
                pmc_memberships=session.committees,
                error=f"Invalid PMC selection: {', '.join(invalid_pmcs)}",
                key_info=None,
                user_keys=user_keys,
                algorithms=algorithms,
            )

        error, key_info = await user_keys_add(session, public_key, selected_pmcs)

    return await render_template(
        "user-keys-add.html",
        asf_id=session.uid,
        pmc_memberships=session.committees,
        error=error,
        key_info=key_info,
        user_keys=user_keys,
        algorithms=algorithms,
    )


@APP.route("/user/keys/delete")
@require(Requirements.committer)
async def root_user_keys_delete() -> str:
    """Debug endpoint to delete all of a user's keys."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    async with get_session() as db_session:
        async with db_session.begin():
            # Get all keys for the user
            # TODO: Use session.apache_uid instead of session.uid?
            statement = select(PublicSigningKey).where(PublicSigningKey.apache_uid == session.uid)
            keys = (await db_session.execute(statement)).scalars().all()
            count = len(keys)

            # Delete all keys
            for key in keys:
                await db_session.delete(key)

        return f"Deleted {count} keys"


@APP.route("/user/uploads")
@require(Requirements.committer)
async def root_user_uploads() -> str:
    """Show all release candidates uploaded by the current user."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    async with get_session() as db_session:
        # Get all releases where the user is a PMC member of the associated PMC
        # TODO: We don't actually record who uploaded the release candidate
        # We should probably add that information!
        release_pmc = selectinload(cast(InstrumentedAttribute[PMC], Release.pmc))
        release_packages = selectinload(cast(InstrumentedAttribute[list[Package]], Release.packages))
        statement = (
            select(Release)
            .options(release_pmc, release_packages)
            .join(PMC)
            .where(Release.stage == ReleaseStage.CANDIDATE)
        )
        releases = (await db_session.execute(statement)).scalars().all()

        # Filter to only show releases for PMCs where the user is a member
        user_releases = []
        for r in releases:
            if r.pmc is None:
                continue
            if session.uid in r.pmc.pmc_members:
                user_releases.append(r)

        return await render_template("user-uploads.html", releases=user_releases)


async def save_file_by_hash(base_dir: Path, file: FileStorage) -> str:
    """
    Save a file using its SHA3-256 hash as the filename.
    Returns the path where the file was saved and its hash.
    """
    sha3 = hashlib.sha3_256()

    # Create temporary file to stream to while computing hash
    temp_path = base_dir / f"temp-{secrets.token_hex(8)}"
    try:
        stream = file.stream

        async with aiofiles.open(temp_path, "wb") as f:
            while True:
                chunk = await asyncio.to_thread(stream.read, 8192)
                if not chunk:
                    break
                sha3.update(chunk)
                await f.write(chunk)

        file_hash = sha3.hexdigest()
        final_path = base_dir / file_hash

        # Only move to final location if it doesn't exist
        # This can race, but it's hash based so it's okay
        if not await aiofiles.os.path.exists(final_path):
            await aiofiles.os.rename(temp_path, final_path)
        else:
            # If file already exists, just remove the temp file
            await aiofiles.os.remove(temp_path)

        return file_hash
    except Exception as e:
        if await aiofiles.os.path.exists(temp_path):
            await aiofiles.os.remove(temp_path)
        raise e


async def user_keys_add(session: ClientSession, public_key: str, selected_pmcs: list[str]) -> tuple[str, dict | None]:
    if not public_key:
        return ("Public key is required", None)

    # Import the key into GPG to validate and extract info
    # TODO: We'll just assume for now that gnupg.GPG() doesn't need to be async
    async with ephemeral_gpg_home() as gpg_home:
        gpg = gnupg.GPG(gnupghome=gpg_home)
        import_result = await asyncio.to_thread(gpg.import_keys, public_key)

        if not import_result.fingerprints:
            return ("Invalid public key format", None)

        fingerprint = import_result.fingerprints[0].lower()
        # APP.logger.info("Import result: %s", vars(import_result))
        # Get key details
        # We could probably use import_result instead
        # But this way it shows that they've really been imported
        keys = await asyncio.to_thread(gpg.list_keys)

    # Then we have the properties listed here:
    # https://gnupg.readthedocs.io/en/latest/#listing-keys
    # Note that "fingerprint" is not listed there, but we have it anyway...
    key = next((k for k in keys if k["fingerprint"].lower() == fingerprint), None)
    if not key:
        return ("Failed to import key", None)
    if (key.get("algo") == "1") and (int(key.get("length", "0")) < 2048):
        # https://infra.apache.org/release-signing.html#note
        # Says that keys must be at least 2048 bits
        return ("Key is not long enough; must be at least 2048 bits", None)

    # Store key in database
    async with get_session() as db_session:
        return await user_keys_add_session(session, public_key, key, selected_pmcs, db_session)


async def user_keys_add_session(
    session: ClientSession,
    public_key: str,
    key: dict,
    selected_pmcs: list[str],
    db_session: AsyncSession,
) -> tuple[str, dict | None]:
    # Check if key already exists
    statement = select(PublicSigningKey).where(PublicSigningKey.apache_uid == session.uid)

    # # If uncommented, this will prevent a user from adding a second key
    # existing_key = (await db_session.execute(statement)).scalar_one_or_none()
    # if existing_key:
    #     return ("You already have a key registered", None)

    if not session.uid:
        return ("You must be signed in to add a key", None)

    uids = key.get("uids")
    async with db_session.begin():
        # Create new key record
        key_record = PublicSigningKey(
            fingerprint=key["fingerprint"].lower(),
            algorithm=int(key["algo"]),
            length=int(key.get("length", "0")),
            created=datetime.datetime.fromtimestamp(int(key["date"])),
            expires=datetime.datetime.fromtimestamp(int(key["expires"])) if key.get("expires") else None,
            declared_uid=uids[0] if uids else None,
            apache_uid=session.uid,
            ascii_armored_key=public_key,
        )
        db_session.add(key_record)

        # Link key to selected PMCs
        for pmc_name in selected_pmcs:
            statement = select(PMC).where(PMC.project_name == pmc_name)
            pmc = (await db_session.execute(statement)).scalar_one_or_none()
            if pmc and pmc.id:
                link = PMCKeyLink(pmc_id=pmc.id, key_fingerprint=key_record.fingerprint)
                db_session.add(link)
            else:
                # TODO: Log? Add to "error"?
                continue

    return (
        "",
        {
            "key_id": key["keyid"],
            "fingerprint": key["fingerprint"].lower(),
            "user_id": key["uids"][0] if key.get("uids") else "Unknown",
            "creation_date": datetime.datetime.fromtimestamp(int(key["date"])),
            "expiration_date": datetime.datetime.fromtimestamp(int(key["expires"])) if key.get("expires") else None,
            "data": pprint.pformat(key),
        },
    )


async def verify_gpg_signature(artifact_path: Path, signature_path: Path, public_keys: list[str]) -> dict[str, Any]:
    """
    Verify a GPG signature for a release artifact.
    Returns a dictionary with verification results and debug information.
    """
    try:
        with open(signature_path, "rb") as sig_file:
            return await verify_gpg_signature_file(sig_file, artifact_path, public_keys)
    except Exception as e:
        return {
            "verified": False,
            "error": str(e),
            "status": "Verification failed",
            "debug_info": {"exception_type": type(e).__name__, "exception_message": str(e)},
        }


async def verify_gpg_signature_file(
    sig_file: BinaryIO, artifact_path: Path, ascii_armored_keys: list[str]
) -> dict[str, Any]:
    """Verify a GPG signature for a file."""
    async with ephemeral_gpg_home() as gpg_home:
        gpg = gnupg.GPG(gnupghome=gpg_home)

        # Import all PMC public signing keys
        for key in ascii_armored_keys:
            import_result = await asyncio.to_thread(gpg.import_keys, key)
            if not import_result.fingerprints:
                # TODO: Log warning about invalid key?
                continue
        verified = await asyncio.to_thread(gpg.verify_file, sig_file, str(artifact_path))

    # Collect all available information for debugging
    debug_info = {
        "key_id": verified.key_id or "Not available",
        "fingerprint": verified.fingerprint.lower() or "Not available",
        "pubkey_fingerprint": verified.pubkey_fingerprint.lower() or "Not available",
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
        return {
            "verified": False,
            "error": "No valid signature found",
            "status": "Invalid signature",
            "debug_info": debug_info,
        }

    return {
        "verified": True,
        "key_id": verified.key_id,
        "timestamp": verified.timestamp,
        "username": verified.username or "Unknown",
        "email": verified.pubkey_fingerprint.lower() or "Unknown",
        "status": "Valid signature",
        "debug_info": debug_info,
    }
