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
import hashlib
import logging
import logging.handlers
import os.path
import pathlib
import secrets
from collections.abc import Sequence

import aiofiles
import aiofiles.os
import asfquart.auth as auth
import asfquart.base as base
import asfquart.session as session
import quart
import werkzeug.datastructures as datastructures
import werkzeug.wrappers.response as response

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.tasks as tasks


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


async def package_data_get(data: db.Session, artifact_sha3: str, release_name: str, session_uid: str) -> models.Package:
    """Validate package deletion request and return the package if valid."""
    # Get the package and its associated release
    package = await data.package(artifact_sha3=artifact_sha3, _release_committee=True).demand(
        routes.FlashError("Package not found")
    )

    if package.release_name != release_name:
        raise routes.FlashError("Invalid release key")

    # Check permissions
    if package.release and package.release.committee:
        if (session_uid not in package.release.committee.committee_members) and (
            session_uid not in package.release.committee.committers
        ):
            raise routes.FlashError("You don't have permission to access this package")

    return package


# Release functions


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
        release_name = form.get("release_name")
    else:
        artifact_sha3 = quart.request.args.get("artifact_sha3")
        release_name = quart.request.args.get("release_name")

    if not artifact_sha3 or not release_name:
        await quart.flash("Missing required parameters", "error")
        return quart.redirect(quart.url_for("root_candidate_review"))

    async with db.session() as data:
        async with data.begin():
            # Get the package and verify permissions
            try:
                package = await package_data_get(data, artifact_sha3, release_name, web_session.uid)
            except routes.FlashError as e:
                logging.exception("FlashError:")
                await quart.flash(str(e), "error")
                return quart.redirect(quart.url_for("root_candidate_review"))

            if quart.request.method == "POST":
                # Check if package already has active tasks
                tasks, has_active_tasks = await task_package_status_get(data, artifact_sha3)
                if has_active_tasks:
                    await quart.flash("Package verification is already in progress", "warning")
                    return quart.redirect(quart.url_for("root_candidate_review"))

                try:
                    await task_verification_create(data, package)
                except routes.FlashError as e:
                    logging.exception("FlashError:")
                    await quart.flash(str(e), "error")
                    return quart.redirect(quart.url_for("root_candidate_review"))

                await quart.flash(f"Added verification tasks for package {package.filename}", "success")
                return quart.redirect(
                    quart.url_for("root_package_check", artifact_sha3=artifact_sha3, release_name=release_name)
                )
            else:
                # Get all tasks for this package for GET request
                tasks, _ = await task_package_status_get(data, artifact_sha3)
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
    release_name = form.get("release_name")

    if not artifact_sha3 or not release_name:
        await quart.flash("Missing required parameters", "error")
        return quart.redirect(quart.url_for("root_candidate_review"))

    async with db.session() as data:
        async with data.begin():
            # Get the package and verify permissions
            try:
                package = await package_data_get(data, artifact_sha3, release_name, web_session.uid)
            except routes.FlashError as e:
                logging.exception("FlashError:")
                await quart.flash(str(e), "error")
                return quart.redirect(quart.url_for("root_candidate_review"))

            # Check if package has any active tasks
            tasks, has_active_tasks = await task_package_status_get(data, artifact_sha3)
            if has_active_tasks:
                await quart.flash("Cannot restart checks while tasks are still in progress", "error")
                return quart.redirect(
                    quart.url_for("root_package_check", artifact_sha3=artifact_sha3, release_name=release_name)
                )

            # Delete existing tasks
            for task in tasks:
                await data.delete(task)

            try:
                await task_verification_create(data, package)
            except routes.FlashError as e:
                logging.exception("FlashError:")
                await quart.flash(str(e), "error")
                return quart.redirect(quart.url_for("root_candidate_review"))

            await quart.flash("Package checks restarted successfully", "success")
            return quart.redirect(
                quart.url_for("root_package_check", artifact_sha3=artifact_sha3, release_name=release_name)
            )


async def task_package_status_get(data: db.Session, artifact_sha3: str) -> tuple[Sequence[models.Task], bool]:
    """
    Get all tasks for a package and determine if any are still in progress.
    Returns tuple[Sequence[Task], bool]: List of tasks and whether any are still in progress
    TODO: Could instead give active count and total count
    """
    tasks = await data.task(package_sha3=artifact_sha3).all()
    has_active_tasks = any(task.status in [models.TaskStatus.QUEUED, models.TaskStatus.ACTIVE] for task in tasks)
    return tasks, has_active_tasks


async def task_verification_create(data: db.Session, package: models.Package) -> None:
    """Create verification tasks for a package."""
    # NOTE: A database session must be open when calling this function
    if not package.release or not package.release.committee:
        raise routes.FlashError("Could not determine committee for package")

    if package.signature_sha3 is None:
        raise routes.FlashError("Package has no signature")

    artifact_path = os.path.join("releases", package.artifact_sha3)
    signature_path = os.path.join("releases", package.signature_sha3)
    committee_name = package.release.committee.name
    artifact_tasks = await tasks.artifact_checks(
        artifact_path, signature_path=signature_path, committee_name=committee_name
    )
    for task in artifact_tasks:
        data.add(task)
