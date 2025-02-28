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

"""download.py"""

import asyncio
import datetime
import hashlib
import pprint
import secrets
import shutil
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import cast

import aiofiles
import aiofiles.os
from quart import Request, flash, redirect, send_file, url_for
from quart.wrappers.response import Response as QuartResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlmodel import select
from werkzeug.datastructures import FileStorage, MultiDict
from werkzeug.wrappers.response import Response

from asfquart import APP
from asfquart.auth import Requirements, require
from asfquart.base import ASFQuartException
from asfquart.session import ClientSession
from asfquart.session import read as session_read
from atr.db import get_session
from atr.db.models import (
    PMC,
    Package,
    PMCKeyLink,
    PublicSigningKey,
    Release,
)
from atr.routes import FlashError, app_route
from atr.util import compute_sha512, get_release_storage_dir


@asynccontextmanager
async def ephemeral_gpg_home() -> AsyncGenerator[str]:
    """Create a temporary directory for an isolated GPG home, and clean it up on exit."""
    # TODO: This is only used in key_user_add
    # We could even inline it there
    temp_dir = await asyncio.to_thread(tempfile.mkdtemp, prefix="gpg-")
    try:
        yield temp_dir
    finally:
        await asyncio.to_thread(shutil.rmtree, temp_dir)


async def file_hash_save(base_dir: Path, file: FileStorage) -> tuple[str, int]:
    """
    Save a file using its SHA3-256 hash as the filename.
    Returns the hash and size in bytes of the saved file.
    """
    sha3 = hashlib.sha3_256()
    total_bytes = 0

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
                total_bytes += len(chunk)
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

        return file_hash, total_bytes
    except Exception as e:
        if await aiofiles.os.path.exists(temp_path):
            await aiofiles.os.remove(temp_path)
        raise e


async def get_form(request: Request) -> MultiDict:
    # The request.form() method in Quart calls a synchronous tempfile method
    # It calls quart.wrappers.request.form _load_form_data
    # Which calls quart.formparser parse and parse_func and parser.parse
    # Which calls _write which calls tempfile, which is synchronous
    # It's getting a tempfile back from some prior call
    # We can't just make blockbuster ignore the call because then it ignores it everywhere

    if APP is ...:
        raise RuntimeError("APP is not set")

    # Or quart.current_app?
    blockbuster = APP.config["blockbuster"]

    # Turn blockbuster off
    if blockbuster is not None:
        blockbuster.deactivate()
    form = await request.form
    # Turn blockbuster on
    if blockbuster is not None:
        blockbuster.activate()
    return form


async def key_user_session_add(
    session: ClientSession,
    public_key: str,
    key: dict,
    selected_pmcs: list[str],
    db_session: AsyncSession,
) -> dict | None:
    # TODO: Check if key already exists
    # psk_statement = select(PublicSigningKey).where(PublicSigningKey.apache_uid == session.uid)

    # # If uncommented, this will prevent a user from adding a second key
    # existing_key = (await db_session.execute(statement)).scalar_one_or_none()
    # if existing_key:
    #     return ("You already have a key registered", None)

    if not session.uid:
        raise FlashError("You must be signed in to add a key")

    fingerprint = key.get("fingerprint")
    if not isinstance(fingerprint, str):
        raise FlashError("Invalid key fingerprint")
    fingerprint = fingerprint.lower()
    uids = key.get("uids")
    async with db_session.begin():
        # Create new key record
        key_record = PublicSigningKey(
            fingerprint=fingerprint,
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
            pmc_statement = select(PMC).where(PMC.project_name == pmc_name)
            pmc = (await db_session.execute(pmc_statement)).scalar_one_or_none()
            if pmc and pmc.id:
                link = PMCKeyLink(pmc_id=pmc.id, key_fingerprint=key_record.fingerprint)
                db_session.add(link)
            else:
                # TODO: Log? Add to "error"?
                continue

    return {
        "key_id": key["keyid"],
        "fingerprint": key["fingerprint"].lower() if key.get("fingerprint") else "Unknown",
        "user_id": key["uids"][0] if key.get("uids") else "Unknown",
        "creation_date": datetime.datetime.fromtimestamp(int(key["date"])),
        "expiration_date": datetime.datetime.fromtimestamp(int(key["expires"])) if key.get("expires") else None,
        "data": pprint.pformat(key),
    }


# Package functions


async def package_add_artifact_info_get(
    db_session: AsyncSession, uploads_path: Path, artifact_file: FileStorage
) -> tuple[str, str, int]:
    """Get artifact information during package addition process.

    Returns a tuple of (sha3_hash, sha512_hash, size) for the artifact file.
    Validates that the artifact hasn't already been uploaded to another release.
    """
    # In a separate function to appease the complexity checker
    artifact_sha3, artifact_size = await file_hash_save(uploads_path, artifact_file)

    # Check for duplicates by artifact_sha3 before proceeding
    package_statement = select(Package).where(Package.artifact_sha3 == artifact_sha3)
    duplicate = (await db_session.execute(package_statement)).first()
    if duplicate:
        # Remove the saved file since we won't be using it
        await aiofiles.os.remove(uploads_path / artifact_sha3)
        raise FlashError("This exact file has already been uploaded to another release")

    # Compute SHA-512 of the artifact for the package record
    return artifact_sha3, await compute_sha512(uploads_path / artifact_sha3), artifact_size


@app_route("/download/<release_key>/<artifact_sha3>")
@require(Requirements.committer)
async def root_download_artifact(release_key: str, artifact_sha3: str) -> Response | QuartResponse:
    """Download an artifact file."""
    # TODO: This function is very similar to the signature download function
    # We should probably extract the common code into a helper function
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    async with get_session() as db_session:
        # Find the package
        package_release = selectinload(cast(InstrumentedAttribute[Release], Package.release))
        release_pmc = package_release.selectinload(cast(InstrumentedAttribute[PMC], Release.pmc))
        package_statement = (
            select(Package)
            .where(Package.artifact_sha3 == artifact_sha3, Package.release_key == release_key)
            .options(release_pmc)
        )
        result = await db_session.execute(package_statement)
        package = result.scalar_one_or_none()

        if not package:
            await flash("Artifact not found", "error")
            return redirect(url_for("root_candidate_review"))

        # Check permissions
        if package.release and package.release.pmc:
            if (session.uid not in package.release.pmc.pmc_members) and (
                session.uid not in package.release.pmc.committers
            ):
                await flash("You don't have permission to download this file", "error")
                return redirect(url_for("root_candidate_review"))

        # Construct file path
        file_path = Path(get_release_storage_dir()) / artifact_sha3

        # Check that the file exists
        if not await aiofiles.os.path.exists(file_path):
            await flash("Artifact file not found", "error")
            return redirect(url_for("root_candidate_review"))

        # Send the file with original filename
        return await send_file(
            file_path, as_attachment=True, attachment_filename=package.filename, mimetype="application/octet-stream"
        )


@app_route("/download/signature/<release_key>/<signature_sha3>")
@require(Requirements.committer)
async def root_download_signature(release_key: str, signature_sha3: str) -> QuartResponse | Response:
    """Download a signature file."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    async with get_session() as db_session:
        # Find the package that has this signature
        package_release = selectinload(cast(InstrumentedAttribute[Release], Package.release))
        release_pmc = package_release.selectinload(cast(InstrumentedAttribute[PMC], Release.pmc))
        package_statement = (
            select(Package)
            .where(Package.signature_sha3 == signature_sha3, Package.release_key == release_key)
            .options(release_pmc)
        )
        result = await db_session.execute(package_statement)
        package = result.scalar_one_or_none()

        if not package:
            await flash("Signature not found", "error")
            return redirect(url_for("root_candidate_review"))

        # Check permissions
        if package.release and package.release.pmc:
            if (session.uid not in package.release.pmc.pmc_members) and (
                session.uid not in package.release.pmc.committers
            ):
                await flash("You don't have permission to download this file", "error")
                return redirect(url_for("root_candidate_review"))

        # Construct file path
        file_path = Path(get_release_storage_dir()) / signature_sha3

        # Check that the file exists
        if not await aiofiles.os.path.exists(file_path):
            await flash("Signature file not found", "error")
            return redirect(url_for("root_candidate_review"))

        # Send the file with original filename and .asc extension
        return await send_file(
            file_path,
            as_attachment=True,
            attachment_filename=f"{package.filename}.asc",
            mimetype="application/pgp-signature",
        )
