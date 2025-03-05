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

"""package.py"""

import asyncio
import datetime
import hashlib
import logging
import logging.handlers
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import aiofiles
import aiofiles.os
from quart import Request, flash, redirect, render_template, request, url_for
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlmodel import select
from werkzeug.datastructures import FileStorage, MultiDict
from werkzeug.wrappers.response import Response

from asfquart.auth import Requirements, require
from asfquart.base import ASFQuartException
from asfquart.session import read as session_read
from atr.db import get_session
from atr.db.models import (
    PMC,
    Package,
    ProductLine,
    Release,
    ReleaseStage,
    Task,
    TaskStatus,
)
from atr.routes import FlashError, app_route, get_form
from atr.util import compute_sha512, get_release_storage_dir


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
    statement = select(Package).where(Package.artifact_sha3 == artifact_sha3)
    duplicate = (await db_session.execute(statement)).first()
    if duplicate:
        # Remove the saved file since we won't be using it
        await aiofiles.os.remove(uploads_path / artifact_sha3)
        raise FlashError("This exact file has already been uploaded to another release")

    # Compute SHA-512 of the artifact for the package record
    return artifact_sha3, await compute_sha512(uploads_path / artifact_sha3), artifact_size


async def package_add_session_process(
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
        artifact_sha3, artifact_sha512, artifact_size = await package_add_artifact_info_get(
            db_session, uploads_path, artifact_file
        )
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
            signature_sha3, _ = await file_hash_save(uploads_path, signature_file)
        except Exception as e:
            await flash(f"Warning: Could not save signature file: {e!s}", "warning")

    return artifact_sha3, artifact_size, artifact_sha512, signature_sha3


async def package_add_validate(
    request: Request,
) -> tuple[str, FileStorage, FileStorage | None, FileStorage | None, str]:
    form = await get_form(request)

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


async def package_data_get(db_session: AsyncSession, artifact_sha3: str, release_key: str, session_uid: str) -> Package:
    """Validate package deletion request and return the package if valid."""
    # Get the package and its associated release
    # if Package.release is None:
    #     raise FlashError("Package has no associated release")
    # if Release.pmc is None:
    #     raise FlashError("Release has no associated PMC")

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
            raise FlashError("You don't have permission to access this package")

    return package


async def package_files_delete(package: Package, uploads_path: Path) -> None:
    """Delete the artifact and signature files associated with a package."""
    if package.artifact_sha3:
        artifact_path = uploads_path / package.artifact_sha3
        if await aiofiles.os.path.exists(artifact_path):
            await aiofiles.os.remove(artifact_path)

    if package.signature_sha3:
        signature_path = uploads_path / package.signature_sha3
        if await aiofiles.os.path.exists(signature_path):
            await aiofiles.os.remove(signature_path)


# Release functions


async def package_add_bulk_validate(form: MultiDict, request: Request) -> tuple[str, str, list[str], bool, int]:
    """Validate bulk package addition form data."""
    release_key = form.get("release_key")
    if (not release_key) or (not isinstance(release_key, str)):
        raise FlashError("Release key is required")

    url = form.get("url")
    if (not url) or (not isinstance(url, str)):
        raise FlashError("URL is required")

    # Validate URL format
    if not url.startswith(("http://", "https://")):
        raise FlashError("URL must start with http:// or https://")

    # Get selected file types
    file_types = form.getlist("file_types")
    if not file_types:
        raise FlashError("At least one file type must be selected")

    # Validate file types
    valid_types = {".tar.gz", ".tgz", ".zip", ".jar"}
    if not all(ft in valid_types for ft in file_types):
        raise FlashError("Invalid file type selected")

    # Get require signatures flag
    require_signatures = bool(form.get("require_signatures"))

    # Get max depth
    try:
        max_depth = int(form.get("max_depth", "1"))
        if not 1 <= max_depth <= 10:
            raise ValueError()
    except (TypeError, ValueError):
        raise FlashError("Maximum depth must be between 1 and 10 inclusive")

    return release_key, url, file_types, require_signatures, max_depth


async def package_add_single_post(form: MultiDict, request: Request) -> Response:
    """Process single package upload submission."""
    try:
        release_key, artifact_file, checksum_file, signature_file, artifact_type = await package_add_validate(request)
    except FlashError as e:
        logging.exception("FlashError:")
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
                    artifact_sha3, artifact_size, artifact_sha512, signature_sha3 = await package_add_session_process(
                        db_session, release_key, artifact_file, checksum_file, signature_file
                    )
                except FlashError as e:
                    logging.exception("FlashError:")
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


async def package_add_bulk_post(form: MultiDict, request: Request) -> Response:
    """Process bulk package URL submission."""
    try:
        release_key, url, file_types, require_signatures, max_depth = await package_add_bulk_validate(form, request)
    except FlashError as e:
        logging.exception("FlashError:")
        await flash(f"{e!s}", "error")
        return redirect(url_for("root_package_add"))

    # Create a task for bulk downloading
    max_concurrency = 5
    async with get_session() as db_session:
        async with db_session.begin():
            task = Task(
                status=TaskStatus.QUEUED,
                task_type="package_bulk_download",
                task_args=[release_key, url, file_types, require_signatures, max_depth, max_concurrency],
            )
            db_session.add(task)
            # Flush to get the task ID
            await db_session.flush()

    await flash("Started downloading packages from URL", "success")
    return redirect(url_for("release_bulk_status", task_id=task.id))


@app_route("/package/add", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_package_add() -> Response | str:
    """Add package artifacts to an existing release."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    # For POST requests, handle the form submission
    if request.method == "POST":
        form = await get_form(request)
        form_type = form.get("form_type")

        if form_type == "bulk":
            return await package_add_bulk_post(form, request)
        else:
            return await package_add_single_post(form, request)

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


@app_route("/package/check", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_package_check() -> str | Response:
    """Show or create package verification tasks."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    # Get parameters from either form data (POST) or query args (GET)
    if request.method == "POST":
        form = await get_form(request)
        artifact_sha3 = form.get("artifact_sha3")
        release_key = form.get("release_key")
    else:
        artifact_sha3 = request.args.get("artifact_sha3")
        release_key = request.args.get("release_key")

    if not artifact_sha3 or not release_key:
        await flash("Missing required parameters", "error")
        return redirect(url_for("root_candidate_review"))

    async with get_session() as db_session:
        async with db_session.begin():
            # Get the package and verify permissions
            try:
                package = await package_data_get(db_session, artifact_sha3, release_key, session.uid)
            except FlashError as e:
                logging.exception("FlashError:")
                await flash(str(e), "error")
                return redirect(url_for("root_candidate_review"))

            if request.method == "POST":
                # Check if package already has active tasks
                tasks, has_active_tasks = await task_package_status_get(db_session, artifact_sha3)
                if has_active_tasks:
                    await flash("Package verification is already in progress", "warning")
                    return redirect(url_for("root_candidate_review"))

                try:
                    await task_verification_create(db_session, package)
                except FlashError as e:
                    logging.exception("FlashError:")
                    await flash(str(e), "error")
                    return redirect(url_for("root_candidate_review"))

                await flash(f"Added verification tasks for package {package.filename}", "success")
                return redirect(url_for("root_package_check", artifact_sha3=artifact_sha3, release_key=release_key))
            else:
                # Get all tasks for this package for GET request
                tasks, _ = await task_package_status_get(db_session, artifact_sha3)
                all_tasks_completed = bool(tasks) and all(
                    task.status == TaskStatus.COMPLETED or task.status == TaskStatus.FAILED for task in tasks
                )
                return await render_template(
                    "package-check.html",
                    package=package,
                    release=package.release,
                    tasks=tasks,
                    all_tasks_completed=all_tasks_completed,
                    format_file_size=format_file_size,
                )


@app_route("/package/check/restart", methods=["POST"])
@require(Requirements.committer)
async def root_package_check_restart() -> Response:
    """Restart package verification tasks."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    form = await get_form(request)
    artifact_sha3 = form.get("artifact_sha3")
    release_key = form.get("release_key")

    if not artifact_sha3 or not release_key:
        await flash("Missing required parameters", "error")
        return redirect(url_for("root_candidate_review"))

    async with get_session() as db_session:
        async with db_session.begin():
            # Get the package and verify permissions
            try:
                package = await package_data_get(db_session, artifact_sha3, release_key, session.uid)
            except FlashError as e:
                logging.exception("FlashError:")
                await flash(str(e), "error")
                return redirect(url_for("root_candidate_review"))

            # Check if package has any active tasks
            tasks, has_active_tasks = await task_package_status_get(db_session, artifact_sha3)
            if has_active_tasks:
                await flash("Cannot restart checks while tasks are still in progress", "error")
                return redirect(url_for("root_package_check", artifact_sha3=artifact_sha3, release_key=release_key))

            # Delete existing tasks
            for task in tasks:
                await db_session.delete(task)

            try:
                await task_verification_create(db_session, package)
            except FlashError as e:
                logging.exception("FlashError:")
                await flash(str(e), "error")
                return redirect(url_for("root_candidate_review"))

            await flash("Package checks restarted successfully", "success")
            return redirect(url_for("root_package_check", artifact_sha3=artifact_sha3, release_key=release_key))


@app_route("/package/delete", methods=["POST"])
@require(Requirements.committer)
async def root_package_delete() -> Response:
    """Delete a package from a release candidate."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    form = await get_form(request)
    artifact_sha3 = form.get("artifact_sha3")
    release_key = form.get("release_key")

    if not artifact_sha3 or not release_key:
        await flash("Missing required parameters", "error")
        return redirect(url_for("root_candidate_review"))

    async with get_session() as db_session:
        async with db_session.begin():
            try:
                package = await package_data_get(db_session, artifact_sha3, release_key, session.uid)
                await package_files_delete(package, Path(get_release_storage_dir()))
                await db_session.delete(package)
            except FlashError as e:
                logging.exception("FlashError:")
                await flash(str(e), "error")
                return redirect(url_for("root_candidate_review"))
            except Exception as e:
                await flash(f"Error deleting files: {e!s}", "error")
                return redirect(url_for("root_candidate_review"))

    await flash("Package deleted successfully", "success")
    return redirect(url_for("root_candidate_review"))


async def task_package_status_get(db_session: AsyncSession, artifact_sha3: str) -> tuple[Sequence[Task], bool]:
    """
    Get all tasks for a package and determine if any are still in progress.
    Returns tuple[Sequence[Task], bool]: List of tasks and whether any are still in progress
    TODO: Could instead give active count and total count
    """
    statement = select(Task).where(Task.package_sha3 == artifact_sha3)
    tasks = (await db_session.execute(statement)).scalars().all()
    has_active_tasks = any(task.status in [TaskStatus.QUEUED, TaskStatus.ACTIVE] for task in tasks)
    return tasks, has_active_tasks


async def task_verification_create(db_session: AsyncSession, package: Package) -> list[Task]:
    """Create verification tasks for a package."""
    if not package.release or not package.release.pmc:
        raise FlashError("Could not determine PMC for package")

    if package.signature_sha3 is None:
        raise FlashError("Package has no signature")

    # TODO: We should probably use an enum for task_type
    tasks = [
        Task(
            status=TaskStatus.QUEUED,
            task_type="verify_archive_integrity",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
        Task(
            status=TaskStatus.QUEUED,
            task_type="verify_archive_structure",
            task_args=["releases/" + package.artifact_sha3, package.filename],
            package_sha3=package.artifact_sha3,
        ),
        Task(
            status=TaskStatus.QUEUED,
            task_type="verify_signature",
            task_args=[
                package.release.pmc.project_name,
                "releases/" + package.artifact_sha3,
                "releases/" + package.signature_sha3,
            ],
            package_sha3=package.artifact_sha3,
        ),
        Task(
            status=TaskStatus.QUEUED,
            task_type="verify_license_files",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
        Task(
            status=TaskStatus.QUEUED,
            task_type="verify_license_headers",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
        Task(
            status=TaskStatus.QUEUED,
            task_type="verify_rat_license",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
        Task(
            status=TaskStatus.QUEUED,
            task_type="generate_cyclonedx_sbom",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
    ]
    for task in tasks:
        db_session.add(task)

    return tasks
