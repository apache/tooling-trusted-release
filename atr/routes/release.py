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

"""release.py"""

import logging
import logging.handlers
from pathlib import Path
from typing import cast

from quart import flash, redirect, render_template, request, url_for
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlmodel import select
from werkzeug.wrappers.response import Response

from asfquart import APP
from asfquart.auth import Requirements, require
from asfquart.base import ASFQuartException
from asfquart.session import read as session_read
from atr.db import create_async_db_session
from atr.db.models import (
    PMC,
    Release,
    Task,
    TaskStatus,
)
from atr.db.service import get_release_by_key
from atr.routes import FlashError, app_route, get_form, package_files_delete
from atr.util import get_release_storage_dir

if APP is ...:
    raise RuntimeError("APP is not set")


# Release functions


async def release_delete_validate(db_session: AsyncSession, release_key: str, session_uid: str) -> Release:
    """Validate release deletion request and return the release if valid."""
    # if Release.pmc is None:
    #     raise FlashError("Release has no associated PMC")

    rel_pmc = cast(InstrumentedAttribute[PMC], Release.pmc)
    statement = select(Release).options(selectinload(rel_pmc)).where(Release.storage_key == release_key)
    result = await db_session.execute(statement)
    release = result.scalar_one_or_none()

    if not release:
        raise FlashError("Release not found")

    # Check permissions
    if release.pmc:
        if (session_uid not in release.pmc.pmc_members) and (session_uid not in release.pmc.committers):
            raise FlashError("You don't have permission to delete this release")

    return release


async def release_files_delete(release: Release, uploads_path: Path) -> None:
    """Delete all files associated with a release."""
    if not release.packages:
        return

    for package in release.packages:
        await package_files_delete(package, uploads_path)


@app_route("/release/delete", methods=["POST"])
@require(Requirements.committer)
async def root_release_delete() -> Response:
    """Delete a release and all its associated packages."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    form = await get_form(request)
    release_key = form.get("release_key")

    if not release_key:
        await flash("Missing required parameters", "error")
        return redirect(url_for("root_candidate_review"))

    async with create_async_db_session() as db_session:
        async with db_session.begin():
            try:
                release = await release_delete_validate(db_session, release_key, session.uid)
                await release_files_delete(release, Path(get_release_storage_dir()))
                await db_session.delete(release)
            except FlashError as e:
                logging.exception("FlashError:")
                await flash(str(e), "error")
                return redirect(url_for("root_candidate_review"))
            except Exception as e:
                await flash(f"Error deleting release: {e!s}", "error")
                return redirect(url_for("root_candidate_review"))

    await flash("Release deleted successfully", "success")
    return redirect(url_for("root_candidate_review"))


@app_route("/release/bulk/<int:task_id>", methods=["GET"])
async def release_bulk_status(task_id: int) -> str | Response:
    """Show status for a bulk download task."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        await flash("You must be logged in to view bulk download status.", "error")
        return redirect(url_for("root_login"))

    async with create_async_db_session() as db_session:
        # Query for the task with the given ID
        query = select(Task).where(Task.id == task_id)
        result = await db_session.execute(query)
        task = result.scalar_one_or_none()

        if not task:
            await flash(f"Task with ID {task_id} not found.", "error")
            return redirect(url_for("root_candidate_review"))

        # Verify this is a bulk download task
        if task.task_type != "package_bulk_download":
            await flash(f"Task with ID {task_id} is not a bulk download task.", "error")
            return redirect(url_for("root_candidate_review"))

        # If result is a list or tuple with a single item, extract it
        if isinstance(task.result, list | tuple) and (len(task.result) == 1):
            task.result = task.result[0]

        # Get the release associated with this task if available
        release = None
        # Debug print the task.task_args using the logger
        logging.debug(f"Task args: {task.task_args}")
        if task.task_args and isinstance(task.task_args, dict) and ("release_key" in task.task_args):
            release_query = select(Release).where(Release.storage_key == task.task_args["release_key"])
            release_result = await db_session.execute(release_query)
            release = release_result.scalar_one_or_none()

            # Check whether the user has permission to view this task
            # Either they're a PMC member or committer for the release's PMC
            if release and release.pmc:
                if (session.uid not in release.pmc.pmc_members) and (session.uid not in release.pmc.committers):
                    await flash("You don't have permission to view this task.", "error")
                    return redirect(url_for("root_candidate_review"))

    return await render_template("release-bulk.html", task=task, release=release, TaskStatus=TaskStatus)


@app_route("/release/vote", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_release_vote() -> Response | str:
    """Show the vote initiation form for a release."""

    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    release_key = request.args.get("release_key", "")
    form = None
    if request.method == "POST":
        form = await get_form(request)
        release_key = form.get("release_key", "")

    if not release_key:
        await flash("No release key provided", "error")
        return redirect(url_for("root_candidate_review"))

    release = await get_release_by_key(release_key)
    if release is None:
        await flash(f"Release with key {release_key} not found", "error")
        return redirect(url_for("root_candidate_review"))

    # If POST, process the form and create a vote_initiate task
    if (request.method == "POST") and (form is not None):
        # Extract form data
        mailing_list = form.get("mailing_list", "dev")
        vote_duration = form.get("vote_duration", "72")
        # These fields are just for testing, we'll do something better in the real UI
        gpg_key_id = form.get("gpg_key_id", "")
        commit_hash = form.get("commit_hash", "")
        if release.pmc is None:
            raise ASFQuartException("Release has no associated PMC", errorcode=400)

        # Prepare email recipient
        email_to = f"{mailing_list}@{release.pmc.project_name}.apache.org"

        # Create a task for vote initiation
        task = Task(
            status=TaskStatus.QUEUED,
            task_type="vote_initiate",
            task_args=[
                release_key,
                email_to,
                vote_duration,
                gpg_key_id,
                commit_hash,
                session.uid,
            ],
        )
        async with create_async_db_session() as db_session:
            db_session.add(task)
            # Flush to get the task ID
            await db_session.flush()
            await db_session.commit()

            await flash(
                f"Vote initiation task queued as task #{task.id}. You'll receive an email confirmation when complete.",
                "success",
            )
            return redirect(url_for("root_candidate_review"))

    # For GET
    return await render_template(
        "release-vote.html",
        release=release,
        email_preview=generate_vote_email_preview(release),
    )


def generate_vote_email_preview(release: Release) -> str:
    """Generate a preview of the vote email."""
    version = release.version

    # Get PMC details
    if release.pmc is None:
        raise ASFQuartException("Release has no associated PMC", errorcode=400)
    pmc_name = release.pmc.project_name
    pmc_display = release.pmc.display_name

    # Get product information
    product_name = release.product_line.product_name if release.product_line else "Unknown"

    # Create email subject
    subject = f"[VOTE] Release Apache {pmc_display} {product_name} {version}"

    # Create email body
    body = f"""Hello {pmc_name},

I'd like to call a vote on releasing the following artifacts as
Apache {pmc_display} {product_name} {version}.

The release candidate can be found at:

https://apache.example.org/{pmc_name}/{product_name}-{version}/

The release artifacts are signed with my GPG key, [KEY_ID].

The artifacts were built from commit:

[COMMIT_HASH]

Please review the release candidate and vote accordingly.

[ ] +1 Release this package
[ ] +0 Abstain
[ ] -1 Do not release this package (please provide specific comments)

This vote will remain open for at least 72 hours.

Thanks,
[YOUR_NAME]
"""
    return f"{subject}\n\n{body}"
