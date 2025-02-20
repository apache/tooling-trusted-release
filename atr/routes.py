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
from quart import Request, flash, redirect, render_template, request, url_for
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlmodel import select
from werkzeug.datastructures import FileStorage
from werkzeug.wrappers.response import Response

from asfquart import APP
from asfquart.auth import Requirements, require
from asfquart.base import ASFQuartException
from asfquart.session import ClientSession
from asfquart.session import read as session_read
from atr.db.models import (
    PMC,
    Package,
    PMCKeyLink,
    ProductLine,
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


class FlashError(RuntimeError): ...


@asynccontextmanager
async def ephemeral_gpg_home():
    """Create a temporary directory for an isolated GPG home, and clean it up on exit."""
    temp_dir = await asyncio.to_thread(tempfile.mkdtemp, prefix="gpg-")
    try:
        yield temp_dir
    finally:
        await asyncio.to_thread(shutil.rmtree, temp_dir)


async def package_add_post(session: ClientSession, request: Request) -> Response:
    """Handle POST request for adding a package to a release."""
    try:
        release_key, artifact_file, checksum_file, signature_file, artifact_type = await package_add_post_validate(
            request
        )
    except FlashError as e:
        await flash(f"{e!s}", "error")
        return redirect(url_for("root_package_add"))
    # This must come here to appease the type checker
    if artifact_file.filename is None:
        await flash("Release artifact filename is required", "error")
        return redirect(url_for("root_package_add"))

    # Save files and create package record in one transaction
    async with get_session() as db_session:
        async with db_session.begin():
            # Process and save the files
            try:
                try:
                    artifact_sha3, artifact_size, artifact_sha512, signature_sha3 = await package_add_post_session(
                        db_session, release_key, artifact_file, checksum_file, signature_file
                    )
                except FlashError as e:
                    await flash(f"{e!s}", "error")
                    return redirect(url_for("root_package_add"))

                # Create the package record
                package = Package(
                    artifact_sha3=artifact_sha3,
                    artifact_type=artifact_type,
                    filename=artifact_file.filename,
                    signature_sha3=signature_sha3,
                    sha512=artifact_sha512,
                    release_key=release_key,
                    uploaded=datetime.datetime.now(datetime.UTC),
                    bytes_size=artifact_size,
                )
                db_session.add(package)

            except Exception as e:
                await flash(f"Error processing files: {e!s}", "error")
                return redirect(url_for("root_package_add"))

    # Otherwise redirect to review page
    return redirect(url_for("root_candidate_review"))


async def package_add_post_validate(
    request: Request,
) -> tuple[str, FileStorage, FileStorage | None, FileStorage | None, str]:
    form = await request.form

    # TODO: Check that the submitter is a committer of the project

    release_key = form.get("release_key")
    if (not release_key) or (not isinstance(release_key, str)):
        raise FlashError("Release key is required")

    # Get all uploaded files
    files = await request.files
    artifact_file = files.get("release_artifact")
    checksum_file = files.get("release_checksum")
    signature_file = files.get("release_signature")
    if not isinstance(artifact_file, FileStorage):
        raise FlashError("Release artifact file is required")
    if checksum_file is not None and not isinstance(checksum_file, FileStorage):
        raise FlashError("Problem with checksum file")
    if signature_file is not None and not isinstance(signature_file, FileStorage):
        raise FlashError("Problem with signature file")

    # Get and validate artifact type
    artifact_type = form.get("artifact_type")
    if (not artifact_type) or (not isinstance(artifact_type, str)):
        raise FlashError("Artifact type is required")
    if artifact_type not in ["source", "binary", "reproducible"]:
        raise FlashError("Invalid artifact type")

    return release_key, artifact_file, checksum_file, signature_file, artifact_type


async def get_artifact_info(
    db_session: AsyncSession, uploads_path: Path, artifact_file: FileStorage
) -> tuple[str, str, int]:
    # In a separate function to appease the complexity checker
    artifact_sha3, artifact_size = await save_file_by_hash(uploads_path, artifact_file)

    # Check for duplicates by artifact_sha3 before proceeding
    statement = select(Package).where(Package.artifact_sha3 == artifact_sha3)
    duplicate = (await db_session.execute(statement)).first()
    if duplicate:
        # Remove the saved file since we won't be using it
        await aiofiles.os.remove(uploads_path / artifact_sha3)
        raise FlashError("This exact file has already been uploaded to another release")

    # Compute SHA-512 of the artifact for the package record
    return artifact_sha3, compute_sha512(uploads_path / artifact_sha3), artifact_size


async def package_add_post_session(
    db_session: AsyncSession,
    release_key: str,
    artifact_file: FileStorage,
    checksum_file: FileStorage | None,
    signature_file: FileStorage | None,
) -> tuple[str, int, str, str | None]:
    """Helper function for package_add_post."""

    # First check for duplicates by filename
    statement = select(Package).where(
        Package.release_key == release_key,
        Package.filename == artifact_file.filename,
    )
    duplicate = (await db_session.execute(statement)).first()

    if duplicate:
        raise FlashError("This release artifact has already been uploaded")

    # Save files using their hashes as filenames
    uploads_path = Path(get_release_storage_dir())
    try:
        artifact_sha3, artifact_sha512, artifact_size = await get_artifact_info(db_session, uploads_path, artifact_file)
    except Exception as e:
        raise FlashError(f"Error saving artifact file: {e!s}")
    # Note: "error" is not permitted past this point
    # Because we don't want to roll back saving the artifact

    # Validate checksum file if provided
    if checksum_file:
        try:
            # Read only the number of bytes required for the checksum
            bytes_required: int = len(artifact_sha512)
            checksum_content = checksum_file.read(bytes_required).decode().strip()
            if checksum_content.lower() != artifact_sha512.lower():
                await flash("Warning: Provided checksum does not match computed SHA-512", "warning")
        except UnicodeDecodeError:
            await flash("Warning: Could not read checksum file as text", "warning")
        except Exception as e:
            await flash(f"Warning: Error validating checksum file: {e!s}", "warning")

    # Process signature file if provided
    signature_sha3 = None
    if signature_file and signature_file.filename:
        if not signature_file.filename.endswith(".asc"):
            await flash("Warning: Signature file should have .asc extension", "warning")
        try:
            signature_sha3, _ = await save_file_by_hash(uploads_path, signature_file)
        except Exception as e:
            await flash(f"Warning: Could not save signature file: {e!s}", "warning")

    return artifact_sha3, artifact_size, artifact_sha512, signature_sha3


async def release_create_post(session: ClientSession, request: Request) -> Response:
    """Handle POST request for creating a new release."""
    form = await request.form

    project_name = form.get("project_name")
    if not project_name:
        raise ASFQuartException("Project name is required", errorcode=400)

    product_name = form.get("product_name")
    if not product_name:
        raise ASFQuartException("Product name is required", errorcode=400)

    version = form.get("version")
    if not version:
        raise ASFQuartException("Version is required", errorcode=400)

    # TODO: Forbid creating a release with an existing project, product, and version
    # Create the release record in the database
    async with get_session() as db_session:
        async with db_session.begin():
            statement = select(PMC).where(PMC.project_name == project_name)
            pmc = (await db_session.execute(statement)).scalar_one_or_none()
            if not pmc:
                APP.logger.error(f"PMC not found for project {project_name}")
                APP.logger.debug(f"Available committees: {session.committees}")
                APP.logger.debug(f"Available projects: {session.projects}")
                raise ASFQuartException("PMC not found", errorcode=404)

            # Verify user is a PMC member or committer of the project
            # We use pmc.display_name, so this must come within the transaction
            if project_name not in session.committees and project_name not in session.projects:
                raise ASFQuartException(
                    f"You must be a PMC member or committer of {pmc.display_name} to submit a release candidate",
                    errorcode=403,
                )

            # Generate a 128-bit random token for the release storage key
            # TODO: Perhaps we should call this the release_key instead
            storage_key = secrets.token_hex(16)

            # Create or get existing product line
            statement = select(ProductLine).where(
                ProductLine.pmc_id == pmc.id, ProductLine.product_name == product_name
            )
            product_line = (await db_session.execute(statement)).scalar_one_or_none()

            if not product_line:
                # Create new product line if it doesn't exist
                product_line = ProductLine(pmc_id=pmc.id, product_name=product_name, latest_version=version)
                db_session.add(product_line)
                # Flush to get the product_line.id
                await db_session.flush()

            # Create release record with product line
            release = Release(
                storage_key=storage_key,
                stage=ReleaseStage.CANDIDATE,
                phase=ReleasePhase.RELEASE_CANDIDATE,
                pmc_id=pmc.id,
                product_line_id=product_line.id,
                version=version,
                created=datetime.datetime.now(datetime.UTC),
            )
            db_session.add(release)

    # Redirect to the add package page with the storage token
    return redirect(url_for("root_package_add", storage_key=storage_key))


@APP.route("/")
async def root() -> str:
    """Main page."""
    return await render_template("index.html")


@APP.route("/package/add", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_package_add() -> Response | str:
    """Add package artifacts to an existing release."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    # For POST requests, handle the file upload
    if request.method == "POST":
        return await package_add_post(session, request)

    # Get the storage_key from the query parameters (if redirected from create)
    storage_key = request.args.get("storage_key")

    # Get all releases where the user is a PMC member or committer of the associated PMC
    async with get_session() as db_session:
        # TODO: This duplicates code in root_candidate_review
        release_pmc = selectinload(cast(InstrumentedAttribute[PMC], Release.pmc))
        release_product_line = selectinload(cast(InstrumentedAttribute[ProductLine], Release.product_line))
        statement = (
            select(Release)
            .options(release_pmc, release_product_line)
            .join(PMC)
            .where(Release.stage == ReleaseStage.CANDIDATE)
        )
        releases = (await db_session.execute(statement)).scalars().all()

        # Filter to only show releases for PMCs or PPMCs where the user is a member or committer
        # Can we do this in sqlmodel using JSON container operators?
        user_releases = []
        for r in releases:
            if r.pmc is None:
                continue
            # For PPMCs the "members" are stored in the committers field
            if session.uid in r.pmc.pmc_members or session.uid in r.pmc.committers:
                user_releases.append(r)

    # For GET requests, show the form
    return await render_template(
        "package-add.html",
        asf_id=session.uid,
        releases=user_releases,
        selected_release=storage_key,
    )


@APP.route("/candidate/create", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_candidate_create() -> Response | str:
    """Create a new release in the database."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    # For POST requests, handle the release creation
    if request.method == "POST":
        return await release_create_post(session, request)

    # Get PMC objects for all projects the user is a member of
    async with get_session() as db_session:
        from sqlalchemy.sql.expression import ColumnElement

        project_list = session.committees + session.projects
        project_name: ColumnElement[str] = cast(ColumnElement[str], PMC.project_name)
        statement = select(PMC).where(project_name.in_(project_list))
        user_pmcs = (await db_session.execute(statement)).scalars().all()

    # For GET requests, show the form
    return await render_template(
        "candidate-create.html",
        asf_id=session.uid,
        user_pmcs=user_pmcs,
    )


@APP.route("/candidate/signatures/verify/<release_key>")
@require(Requirements.committer)
async def root_candidate_signatures_verify(release_key: str) -> str:
    """Verify the signatures for all packages in a release candidate."""
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
            result = {"file": package.artifact_sha3}

            artifact_path = storage_dir / package.artifact_sha3
            if package.signature_sha3 is None:
                result["error"] = "No signature file provided"
                verification_results.append(result)
                continue

            signature_path = storage_dir / package.signature_sha3

            if not artifact_path.exists():
                result["error"] = "Package artifact file not found"
            elif not signature_path.exists():
                result["error"] = "Package signature file not found"
            else:
                # Verify the signature
                result = await verify_gpg_signature(artifact_path, signature_path, ascii_armored_keys)
                result["file"] = package.artifact_sha3

            verification_results.append(result)

        return await render_template(
            "candidate-signature-verify.html", release=release, verification_results=verification_results
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


@APP.route("/keys/review")
@require(Requirements.committer)
async def root_keys_review() -> str:
    """Show all keys associated with the user's account."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    # Get all existing keys for the user
    async with get_session() as db_session:
        pmcs_loader = selectinload(cast(InstrumentedAttribute[list[PMC]], PublicSigningKey.pmcs))
        statement = select(PublicSigningKey).options(pmcs_loader).where(PublicSigningKey.apache_uid == session.uid)
        user_keys = (await db_session.execute(statement)).scalars().all()

    status_message = request.args.get("status_message")
    status_type = request.args.get("status_type")

    return await render_template(
        "keys-review.html",
        asf_id=session.uid,
        user_keys=user_keys,
        algorithms=algorithms,
        status_message=status_message,
        status_type=status_type,
    )


@APP.route("/keys/delete", methods=["POST"])
@require(Requirements.committer)
async def root_keys_delete() -> Response:
    """Delete a public signing key from the user's account."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    form = await request.form
    fingerprint = form.get("fingerprint")
    if not fingerprint:
        await flash("No key fingerprint provided", "error")
        return redirect(url_for("root_keys_review"))

    async with get_session() as db_session:
        async with db_session.begin():
            # Get the key and verify ownership
            statement = select(PublicSigningKey).where(
                PublicSigningKey.fingerprint == fingerprint, PublicSigningKey.apache_uid == session.uid
            )
            key = (await db_session.execute(statement)).scalar_one_or_none()

            if not key:
                await flash("Key not found or not owned by you", "error")
                return redirect(url_for("root_keys_review"))

            # Delete the key
            await db_session.delete(key)

    await flash("Key deleted successfully", "success")
    return redirect(url_for("root_keys_review"))


@APP.route("/keys/add", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_keys_add() -> str:
    """Add a new public signing key to the user's account."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    error = None
    key_info = None

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
                "keys-add.html",
                asf_id=session.uid,
                pmc_memberships=session.committees,
                error="You must select at least one PMC",
                key_info=None,
                algorithms=algorithms,
                committer_projects=session.projects,
            )

        # Ensure that the selected PMCs are ones of which the user is actually a member
        invalid_pmcs = [
            pmc for pmc in selected_pmcs if (pmc not in session.committees) and (pmc not in session.projects)
        ]
        if invalid_pmcs:
            return await render_template(
                "keys-add.html",
                asf_id=session.uid,
                pmc_memberships=session.committees,
                error=f"Invalid PMC selection: {', '.join(invalid_pmcs)}",
                key_info=None,
                algorithms=algorithms,
                committer_projects=session.projects,
            )

        error, key_info = await user_keys_add(session, public_key, selected_pmcs)

    return await render_template(
        "keys-add.html",
        asf_id=session.uid,
        pmc_memberships=session.committees,
        error=error,
        key_info=key_info,
        algorithms=algorithms,
        committer_projects=session.projects,
    )


def format_file_size(size_in_bytes: int) -> str:
    """Format a file size with appropriate units and comma-separated digits."""
    # Format the raw bytes with commas
    formatted_bytes = f"{size_in_bytes:,}"

    # Calculate the appropriate unit
    if size_in_bytes >= 1_000_000_000:
        size_in_gb = size_in_bytes // 1_000_000_000
        return f"{size_in_gb:,} GB ({formatted_bytes} bytes)"
    elif size_in_bytes >= 1_000_000:
        size_in_mb = size_in_bytes // 1_000_000
        return f"{size_in_mb:,} MB ({formatted_bytes} bytes)"
    elif size_in_bytes >= 1_000:
        size_in_kb = size_in_bytes // 1_000
        return f"{size_in_kb:,} KB ({formatted_bytes} bytes)"
    else:
        return f"{formatted_bytes} bytes"


def format_artifact_name(project_name: str, product_name: str, version: str, is_podling: bool = False) -> str:
    """Format an artifact name according to Apache naming conventions.

    For regular projects: apache-${project}-${product}-${version}
    For podlings: apache-${project}-incubating-${product}-${version}
    """
    if is_podling:
        return f"apache-{project_name}-incubating-{product_name}-{version}"
    return f"apache-{project_name}-{product_name}-{version}"


@APP.route("/candidate/review")
@require(Requirements.committer)
async def root_candidate_review() -> str:
    """Show all release candidates to which the user has access."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    async with get_session() as db_session:
        # Get all releases where the user is a PMC member or committer
        # TODO: We don't actually record who uploaded the release candidate
        # We should probably add that information!
        # TODO: This duplicates code in root_package_add
        release_pmc = selectinload(cast(InstrumentedAttribute[PMC], Release.pmc))
        release_packages = selectinload(cast(InstrumentedAttribute[list[Package]], Release.packages))
        release_product_line = selectinload(cast(InstrumentedAttribute[ProductLine], Release.product_line))
        statement = (
            select(Release)
            .options(release_pmc, release_packages, release_product_line)
            .join(PMC)
            .where(Release.stage == ReleaseStage.CANDIDATE)
        )
        releases = (await db_session.execute(statement)).scalars().all()

        # Filter to only show releases for PMCs or PPMCs where the user is a member or committer
        user_releases = []
        for r in releases:
            if r.pmc is None:
                continue
            # For PPMCs the "members" are stored in the committers field
            if session.uid in r.pmc.pmc_members or session.uid in r.pmc.committers:
                user_releases.append(r)

        return await render_template(
            "candidate-review.html",
            releases=user_releases,
            format_file_size=format_file_size,
            format_artifact_name=format_artifact_name,
        )


async def delete_package_files(package: Package, uploads_path: Path) -> None:
    """Delete the artifact and signature files associated with a package."""
    if package.artifact_sha3:
        artifact_path = uploads_path / package.artifact_sha3
        if await aiofiles.os.path.exists(artifact_path):
            await aiofiles.os.remove(artifact_path)

    if package.signature_sha3:
        signature_path = uploads_path / package.signature_sha3
        if await aiofiles.os.path.exists(signature_path):
            await aiofiles.os.remove(signature_path)


async def validate_package_deletion(
    db_session: AsyncSession, artifact_sha3: str, release_key: str, session_uid: str
) -> Package:
    """Validate package deletion request and return the package if valid."""
    # Get the package and its associated release
    if Package.release is None:
        raise FlashError("Package has no associated release")
    if Release.pmc is None:
        raise FlashError("Release has no associated PMC")

    pkg_release = cast(InstrumentedAttribute[Release], Package.release)
    rel_pmc = cast(InstrumentedAttribute[PMC], Release.pmc)
    statement = (
        select(Package)
        .options(selectinload(pkg_release).selectinload(rel_pmc))
        .where(Package.artifact_sha3 == artifact_sha3)
    )
    result = await db_session.execute(statement)
    package = result.scalar_one_or_none()

    if not package:
        raise FlashError("Package not found")

    if package.release_key != release_key:
        raise FlashError("Invalid release key")

    # Check permissions
    if package.release and package.release.pmc:
        if session_uid not in package.release.pmc.pmc_members and session_uid not in package.release.pmc.committers:
            raise FlashError("You don't have permission to delete this package")

    return package


@APP.route("/package/delete", methods=["POST"])
@require(Requirements.committer)
async def root_package_delete() -> Response:
    """Delete a package from a release candidate."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    form = await request.form
    artifact_sha3 = form.get("artifact_sha3")
    release_key = form.get("release_key")

    if not artifact_sha3 or not release_key:
        await flash("Missing required parameters", "error")
        return redirect(url_for("root_candidate_review"))

    async with get_session() as db_session:
        async with db_session.begin():
            try:
                package = await validate_package_deletion(db_session, artifact_sha3, release_key, session.uid)
                await delete_package_files(package, Path(get_release_storage_dir()))
                await db_session.delete(package)
            except FlashError as e:
                await flash(str(e), "error")
                return redirect(url_for("root_candidate_review"))
            except Exception as e:
                await flash(f"Error deleting files: {e!s}", "error")
                return redirect(url_for("root_candidate_review"))

    await flash("Package deleted successfully", "success")
    return redirect(url_for("root_candidate_review"))


async def save_file_by_hash(base_dir: Path, file: FileStorage) -> tuple[str, int]:
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

        fingerprint = import_result.fingerprints[0]
        if fingerprint is not None:
            fingerprint = fingerprint.lower()
        # APP.logger.info("Import result: %s", vars(import_result))
        # Get key details
        # We could probably use import_result instead
        # But this way it shows that they've really been imported
        keys = await asyncio.to_thread(gpg.list_keys)

    # Then we have the properties listed here:
    # https://gnupg.readthedocs.io/en/latest/#listing-keys
    # Note that "fingerprint" is not listed there, but we have it anyway...
    key = next((k for k in keys if (k["fingerprint"] is not None) and (k["fingerprint"].lower() == fingerprint)), None)
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

    fingerprint = key.get("fingerprint")
    if not isinstance(fingerprint, str):
        return ("Invalid key fingerprint", None)
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
            "fingerprint": key["fingerprint"].lower() if key.get("fingerprint") else "Unknown",
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


async def validate_release_deletion(db_session: AsyncSession, release_key: str, session_uid: str) -> Release:
    """Validate release deletion request and return the release if valid."""
    if Release.pmc is None:
        raise FlashError("Release has no associated PMC")

    rel_pmc = cast(InstrumentedAttribute[PMC], Release.pmc)
    statement = select(Release).options(selectinload(rel_pmc)).where(Release.storage_key == release_key)
    result = await db_session.execute(statement)
    release = result.scalar_one_or_none()

    if not release:
        raise FlashError("Release not found")

    # Check permissions
    if release.pmc:
        if session_uid not in release.pmc.pmc_members and session_uid not in release.pmc.committers:
            raise FlashError("You don't have permission to delete this release")

    return release


async def delete_release_files(release: Release, uploads_path: Path) -> None:
    """Delete all files associated with a release."""
    if not release.packages:
        return

    for package in release.packages:
        await delete_package_files(package, uploads_path)


@APP.route("/release/delete", methods=["POST"])
@require(Requirements.committer)
async def root_release_delete() -> Response:
    """Delete a release and all its associated packages."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    form = await request.form
    release_key = form.get("release_key")

    if not release_key:
        await flash("Missing required parameters", "error")
        return redirect(url_for("root_candidate_review"))

    async with get_session() as db_session:
        async with db_session.begin():
            try:
                release = await validate_release_deletion(db_session, release_key, session.uid)
                await delete_release_files(release, Path(get_release_storage_dir()))
                await db_session.delete(release)
            except FlashError as e:
                await flash(str(e), "error")
                return redirect(url_for("root_candidate_review"))
            except Exception as e:
                await flash(f"Error deleting release: {e!s}", "error")
                return redirect(url_for("root_candidate_review"))

    await flash("Release deleted successfully", "success")
    return redirect(url_for("root_candidate_review"))
