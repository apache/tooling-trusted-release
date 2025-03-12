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
import pathlib
import secrets
from collections.abc import Sequence

import aiofiles
import aiofiles.os
import quart
import sqlalchemy.ext.asyncio
import sqlmodel
import werkzeug.datastructures as datastructures
import werkzeug.wrappers.response as response

import asfquart.auth as auth
import asfquart.base as base
import asfquart.session as session
import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.tasks.archive as archive
import atr.util as util


async def file_hash_save(base_dir: pathlib.Path, file: datastructures.FileStorage) -> tuple[str, int]:
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


# Package functions


async def package_add_artifact_info_get(
    db_session: sqlalchemy.ext.asyncio.AsyncSession,
    uploads_path: pathlib.Path,
    artifact_file: datastructures.FileStorage,
) -> tuple[str, str, int]:
    """Get artifact information during package addition process.

    Returns a tuple of (sha3_hash, sha512_hash, size) for the artifact file.
    Validates that the artifact hasn't already been uploaded to another release.
    """
    # In a separate function to appease the complexity checker
    artifact_sha3, artifact_size = await file_hash_save(uploads_path, artifact_file)

    # Check for duplicates by artifact_sha3 before proceeding
    statement = sqlmodel.select(models.Package).where(models.Package.artifact_sha3 == artifact_sha3)
    duplicate = (await db_session.execute(statement)).first()
    if duplicate:
        # Remove the saved file since we won't be using it
        await aiofiles.os.remove(uploads_path / artifact_sha3)
        raise routes.FlashError("This exact file has already been uploaded to another release")

    # Compute SHA-512 of the artifact for the package record
    return artifact_sha3, await util.compute_sha512(uploads_path / artifact_sha3), artifact_size


async def package_add_session_process(
    db_session: sqlalchemy.ext.asyncio.AsyncSession,
    release_key: str,
    artifact_file: datastructures.FileStorage,
    checksum_file: datastructures.FileStorage | None,
    signature_file: datastructures.FileStorage | None,
) -> tuple[str, int, str, str | None]:
    """Helper function for package_add_post."""

    # First check for duplicates by filename
    statement = sqlmodel.select(models.Package).where(
        models.Package.release_key == release_key,
        models.Package.filename == artifact_file.filename,
    )
    duplicate = (await db_session.execute(statement)).first()

    if duplicate:
        raise routes.FlashError("This release artifact has already been uploaded")

    # Save files using their hashes as filenames
    uploads_path = pathlib.Path(util.get_release_storage_dir())
    try:
        artifact_sha3, artifact_sha512, artifact_size = await package_add_artifact_info_get(
            db_session, uploads_path, artifact_file
        )
    except Exception as e:
        raise routes.FlashError(f"Error saving artifact file: {e!s}")
    # Note: "error" is not permitted past this point
    # Because we don't want to roll back saving the artifact

    # Validate checksum file if provided
    if checksum_file:
        try:
            # Read only the number of bytes required for the checksum
            bytes_required: int = len(artifact_sha512)
            checksum_content = checksum_file.read(bytes_required).decode().strip()
            if checksum_content.lower() != artifact_sha512.lower():
                await quart.flash("Warning: Provided checksum does not match computed SHA-512", "warning")
        except UnicodeDecodeError:
            await quart.flash("Warning: Could not read checksum file as text", "warning")
        except Exception as e:
            await quart.flash(f"Warning: Error validating checksum file: {e!s}", "warning")

    # Process signature file if provided
    signature_sha3 = None
    if signature_file and signature_file.filename:
        if not signature_file.filename.endswith(".asc"):
            await quart.flash("Warning: Signature file should have .asc extension", "warning")
        try:
            signature_sha3, _ = await file_hash_save(uploads_path, signature_file)
        except Exception as e:
            await quart.flash(f"Warning: Could not save signature file: {e!s}", "warning")

    return artifact_sha3, artifact_size, artifact_sha512, signature_sha3


async def package_add_validate(
    request: quart.Request,
) -> tuple[str, datastructures.FileStorage, datastructures.FileStorage | None, datastructures.FileStorage | None, str]:
    form = await routes.get_form(request)

    # TODO: Check that the submitter is a committer of the project

    release_key = form.get("release_key")
    if (not release_key) or (not isinstance(release_key, str)):
        raise routes.FlashError("Release key is required")

    # Get all uploaded files
    files = await request.files
    artifact_file = files.get("release_artifact")
    checksum_file = files.get("release_checksum")
    signature_file = files.get("release_signature")
    if not isinstance(artifact_file, datastructures.FileStorage):
        raise routes.FlashError("Release artifact file is required")
    if checksum_file is not None and not isinstance(checksum_file, datastructures.FileStorage):
        raise routes.FlashError("Problem with checksum file")
    if signature_file is not None and not isinstance(signature_file, datastructures.FileStorage):
        raise routes.FlashError("Problem with signature file")

    # Get and validate artifact type
    artifact_type = form.get("artifact_type")
    if (not artifact_type) or (not isinstance(artifact_type, str)):
        raise routes.FlashError("Artifact type is required")
    if artifact_type not in ["source", "binary", "reproducible"]:
        raise routes.FlashError("Invalid artifact type")

    return release_key, artifact_file, checksum_file, signature_file, artifact_type


async def package_data_get(
    db_session: sqlalchemy.ext.asyncio.AsyncSession, artifact_sha3: str, release_key: str, session_uid: str
) -> models.Package:
    """Validate package deletion request and return the package if valid."""
    # Get the package and its associated release
    # if Package.release is None:
    #     raise FlashError("Package has no associated release")
    # if Release.pmc is None:
    #     raise FlashError("Release has no associated PMC")
    statement = (
        sqlmodel.select(models.Package)
        .options(db.select_in_load_nested(models.Package.release, models.Release.pmc))
        .where(models.Package.artifact_sha3 == artifact_sha3)
    )
    result = await db_session.execute(statement)
    package = result.scalar_one_or_none()

    if not package:
        raise routes.FlashError("Package not found")

    if package.release_key != release_key:
        raise routes.FlashError("Invalid release key")

    # Check permissions
    if package.release and package.release.pmc:
        if session_uid not in package.release.pmc.pmc_members and session_uid not in package.release.pmc.committers:
            raise routes.FlashError("You don't have permission to access this package")

    return package


# Release functions


async def package_add_bulk_validate(
    form: datastructures.MultiDict, request: quart.Request
) -> tuple[str, str, list[str], bool, int]:
    """Validate bulk package addition form data."""
    release_key = form.get("release_key")
    if (not release_key) or (not isinstance(release_key, str)):
        raise routes.FlashError("Release key is required")

    url = form.get("url")
    if (not url) or (not isinstance(url, str)):
        raise routes.FlashError("URL is required")

    # Validate URL format
    if not url.startswith(("http://", "https://")):
        raise routes.FlashError("URL must start with http:// or https://")

    # Get selected file types
    file_types = form.getlist("file_types")
    if not file_types:
        raise routes.FlashError("At least one file type must be selected")

    # Validate file types
    valid_types = {".tar.gz", ".tgz", ".zip", ".jar"}
    if not all(ft in valid_types for ft in file_types):
        raise routes.FlashError("Invalid file type selected")

    # Get require signatures flag
    require_signatures = bool(form.get("require_signatures"))

    # Get max depth
    try:
        max_depth = int(form.get("max_depth", "1"))
        if not 1 <= max_depth <= 10:
            raise ValueError()
    except (TypeError, ValueError):
        raise routes.FlashError("Maximum depth must be between 1 and 10 inclusive")

    return release_key, url, file_types, require_signatures, max_depth


async def package_add_single_post(form: datastructures.MultiDict, request: quart.Request) -> response.Response:
    """Process single package upload submission."""
    try:
        release_key, artifact_file, checksum_file, signature_file, artifact_type = await package_add_validate(request)
    except routes.FlashError as e:
        logging.exception("FlashError:")
        await quart.flash(f"{e!s}", "error")
        return quart.redirect(quart.url_for("root_package_add"))
    # This must come here to appease the type checker
    if artifact_file.filename is None:
        await quart.flash("Release artifact filename is required", "error")
        return quart.redirect(quart.url_for("root_package_add"))

    # Save files and create package record in one transaction
    async with db.create_async_db_session() as db_session:
        async with db_session.begin():
            # Process and save the files
            try:
                try:
                    artifact_sha3, artifact_size, artifact_sha512, signature_sha3 = await package_add_session_process(
                        db_session, release_key, artifact_file, checksum_file, signature_file
                    )
                except routes.FlashError as e:
                    logging.exception("FlashError:")
                    await quart.flash(f"{e!s}", "error")
                    return quart.redirect(quart.url_for("root_package_add"))

                # Create the package record
                package = models.Package(
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
                await quart.flash(f"Error processing files: {e!s}", "error")
                return quart.redirect(quart.url_for("root_package_add"))

    # Otherwise redirect to review page
    return quart.redirect(quart.url_for("root_candidate_review"))


async def package_add_bulk_post(form: datastructures.MultiDict, request: quart.Request) -> response.Response:
    """Process bulk package URL submission."""
    try:
        release_key, url, file_types, require_signatures, max_depth = await package_add_bulk_validate(form, request)
    except routes.FlashError as e:
        logging.exception("FlashError:")
        await quart.flash(f"{e!s}", "error")
        return quart.redirect(quart.url_for("root_package_add"))

    # Create a task for bulk downloading
    max_concurrency = 5
    async with db.create_async_db_session() as db_session:
        async with db_session.begin():
            task = models.Task(
                status=models.TaskStatus.QUEUED,
                task_type="package_bulk_download",
                task_args=[release_key, url, file_types, require_signatures, max_depth, max_concurrency],
            )
            db_session.add(task)
            # Flush to get the task ID
            await db_session.flush()

    await quart.flash("Started downloading packages from URL", "success")
    return quart.redirect(quart.url_for("release_bulk_status", task_id=task.id))


@routes.app_route("/package/add", methods=["GET", "POST"])
@auth.require(auth.Requirements.committer)
async def root_package_add() -> response.Response | str:
    """Add package artifacts to an existing release."""
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    # For POST requests, handle the form submission
    if quart.request.method == "POST":
        form = await routes.get_form(quart.request)
        form_type = form.get("form_type")

        if form_type == "bulk":
            return await package_add_bulk_post(form, quart.request)
        else:
            return await package_add_single_post(form, quart.request)

    # Get the storage_key from the query parameters (if redirected from create)
    storage_key = quart.request.args.get("storage_key")

    # Get all releases where the user is a PMC member or committer of the associated PMC
    async with db.create_async_db_session() as db_session:
        # TODO: This duplicates code in root_candidate_review
        release_pmc = db.select_in_load(models.Release.pmc)
        release_product_line = db.select_in_load(models.Release.product_line)
        statement = (
            sqlmodel.select(models.Release)
            .options(release_pmc, release_product_line)
            .join(models.PMC)
            .where(models.Release.stage == models.ReleaseStage.CANDIDATE)
        )
        releases = (await db_session.execute(statement)).scalars().all()

        # Filter to only show releases for PMCs or PPMCs where the user is a member or committer
        # Can we do this in sqlmodel using JSON container operators?
        user_releases = []
        for r in releases:
            if r.pmc is None:
                continue
            # For PPMCs the "members" are stored in the committers field
            if web_session.uid in r.pmc.pmc_members or web_session.uid in r.pmc.committers:
                user_releases.append(r)

    # For GET requests, show the form
    return await quart.render_template(
        "package-add.html",
        asf_id=web_session.uid,
        releases=user_releases,
        selected_release=storage_key,
    )


@routes.app_route("/package/check", methods=["GET", "POST"])
@auth.require(auth.Requirements.committer)
async def root_package_check() -> str | response.Response:
    """Show or create package verification tasks."""
    web_session = await session.read()
    if (web_session is None) or (web_session.uid is None):
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    # Get parameters from either form data (POST) or query args (GET)
    if quart.request.method == "POST":
        form = await routes.get_form(quart.request)
        artifact_sha3 = form.get("artifact_sha3")
        release_key = form.get("release_key")
    else:
        artifact_sha3 = quart.request.args.get("artifact_sha3")
        release_key = quart.request.args.get("release_key")

    if not artifact_sha3 or not release_key:
        await quart.flash("Missing required parameters", "error")
        return quart.redirect(quart.url_for("root_candidate_review"))

    async with db.create_async_db_session() as db_session:
        async with db_session.begin():
            # Get the package and verify permissions
            try:
                package = await package_data_get(db_session, artifact_sha3, release_key, web_session.uid)
            except routes.FlashError as e:
                logging.exception("FlashError:")
                await quart.flash(str(e), "error")
                return quart.redirect(quart.url_for("root_candidate_review"))

            if quart.request.method == "POST":
                # Check if package already has active tasks
                tasks, has_active_tasks = await task_package_status_get(db_session, artifact_sha3)
                if has_active_tasks:
                    await quart.flash("Package verification is already in progress", "warning")
                    return quart.redirect(quart.url_for("root_candidate_review"))

                try:
                    await task_verification_create(db_session, package)
                except routes.FlashError as e:
                    logging.exception("FlashError:")
                    await quart.flash(str(e), "error")
                    return quart.redirect(quart.url_for("root_candidate_review"))

                await quart.flash(f"Added verification tasks for package {package.filename}", "success")
                return quart.redirect(
                    quart.url_for("root_package_check", artifact_sha3=artifact_sha3, release_key=release_key)
                )
            else:
                # Get all tasks for this package for GET request
                tasks, _ = await task_package_status_get(db_session, artifact_sha3)
                all_tasks_completed = bool(tasks) and all(
                    task.status == models.TaskStatus.COMPLETED or task.status == models.TaskStatus.FAILED
                    for task in tasks
                )
                return await quart.render_template(
                    "package-check.html",
                    package=package,
                    release=package.release,
                    tasks=tasks,
                    all_tasks_completed=all_tasks_completed,
                    format_file_size=routes.format_file_size,
                )


@routes.app_route("/package/check/restart", methods=["POST"])
@auth.require(auth.Requirements.committer)
async def root_package_check_restart() -> response.Response:
    """Restart package verification tasks."""
    web_session = await session.read()
    if (web_session is None) or (web_session.uid is None):
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    form = await routes.get_form(quart.request)
    artifact_sha3 = form.get("artifact_sha3")
    release_key = form.get("release_key")

    if not artifact_sha3 or not release_key:
        await quart.flash("Missing required parameters", "error")
        return quart.redirect(quart.url_for("root_candidate_review"))

    async with db.create_async_db_session() as db_session:
        async with db_session.begin():
            # Get the package and verify permissions
            try:
                package = await package_data_get(db_session, artifact_sha3, release_key, web_session.uid)
            except routes.FlashError as e:
                logging.exception("FlashError:")
                await quart.flash(str(e), "error")
                return quart.redirect(quart.url_for("root_candidate_review"))

            # Check if package has any active tasks
            tasks, has_active_tasks = await task_package_status_get(db_session, artifact_sha3)
            if has_active_tasks:
                await quart.flash("Cannot restart checks while tasks are still in progress", "error")
                return quart.redirect(
                    quart.url_for("root_package_check", artifact_sha3=artifact_sha3, release_key=release_key)
                )

            # Delete existing tasks
            for task in tasks:
                await db_session.delete(task)

            try:
                await task_verification_create(db_session, package)
            except routes.FlashError as e:
                logging.exception("FlashError:")
                await quart.flash(str(e), "error")
                return quart.redirect(quart.url_for("root_candidate_review"))

            await quart.flash("Package checks restarted successfully", "success")
            return quart.redirect(
                quart.url_for("root_package_check", artifact_sha3=artifact_sha3, release_key=release_key)
            )


@routes.app_route("/package/delete", methods=["POST"])
@auth.require(auth.Requirements.committer)
async def root_package_delete() -> response.Response:
    """Delete a package from a release candidate."""
    web_session = await session.read()
    if (web_session is None) or (web_session.uid is None):
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    form = await routes.get_form(quart.request)
    artifact_sha3 = form.get("artifact_sha3")
    release_key = form.get("release_key")

    if not artifact_sha3 or not release_key:
        await quart.flash("Missing required parameters", "error")
        return quart.redirect(quart.url_for("root_candidate_review"))

    async with db.create_async_db_session() as db_session:
        async with db_session.begin():
            try:
                package = await package_data_get(db_session, artifact_sha3, release_key, web_session.uid)
                await routes.package_files_delete(package, pathlib.Path(util.get_release_storage_dir()))
                await db_session.delete(package)
            except routes.FlashError as e:
                logging.exception("FlashError:")
                await quart.flash(str(e), "error")
                return quart.redirect(quart.url_for("root_candidate_review"))
            except Exception as e:
                await quart.flash(f"Error deleting files: {e!s}", "error")
                return quart.redirect(quart.url_for("root_candidate_review"))

    await quart.flash("Package deleted successfully", "success")
    return quart.redirect(quart.url_for("root_candidate_review"))


async def task_package_status_get(
    db_session: sqlalchemy.ext.asyncio.AsyncSession, artifact_sha3: str
) -> tuple[Sequence[models.Task], bool]:
    """
    Get all tasks for a package and determine if any are still in progress.
    Returns tuple[Sequence[Task], bool]: List of tasks and whether any are still in progress
    TODO: Could instead give active count and total count
    """
    statement = sqlmodel.select(models.Task).where(models.Task.package_sha3 == artifact_sha3)
    tasks = (await db_session.execute(statement)).scalars().all()
    has_active_tasks = any(task.status in [models.TaskStatus.QUEUED, models.TaskStatus.ACTIVE] for task in tasks)
    return tasks, has_active_tasks


async def task_verification_create(
    db_session: sqlalchemy.ext.asyncio.AsyncSession, package: models.Package
) -> list[models.Task]:
    """Create verification tasks for a package."""
    if not package.release or not package.release.pmc:
        raise routes.FlashError("Could not determine PMC for package")

    if package.signature_sha3 is None:
        raise routes.FlashError("Package has no signature")

    # TODO: We should probably use an enum for task_type
    tasks = [
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_archive_integrity",
            task_args=archive.CheckIntegrity(path="releases/" + package.artifact_sha3).model_dump(),
            package_sha3=package.artifact_sha3,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_archive_structure",
            task_args=["releases/" + package.artifact_sha3, package.filename],
            package_sha3=package.artifact_sha3,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_signature",
            task_args=[
                package.release.pmc.project_name,
                "releases/" + package.artifact_sha3,
                "releases/" + package.signature_sha3,
            ],
            package_sha3=package.artifact_sha3,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_license_files",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_license_headers",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="verify_rat_license",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
        models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="generate_cyclonedx_sbom",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
    ]
    for task in tasks:
        db_session.add(task)

    return tasks
