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
