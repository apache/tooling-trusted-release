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

import aiofiles.os
import aioshutil
import asfquart
import quart
import werkzeug.wrappers.response as response

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.routes.candidate as candidate
import atr.util as util

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")


# Release functions


async def release_delete_validate(data: db.Session, release_name: str, session_uid: str) -> models.Release:
    """Validate release deletion request and return the release if valid."""
    release = await data.release(name=release_name, _committee=True, _packages=True).demand(
        routes.FlashError("Release not found")
    )

    # Check permissions
    if release.committee:
        if (session_uid not in release.committee.committee_members) and (
            session_uid not in release.committee.committers
        ):
            raise routes.FlashError("You don't have permission to delete this release")

    return release


@routes.committer("/release/delete", methods=["POST"])
async def delete(session: routes.CommitterSession) -> response.Response:
    """Delete a release and all its associated files."""
    form = await routes.get_form(quart.request)
    release_name = form.get("release_name")

    if not release_name:
        return await session.redirect(candidate.vote, error="Missing required parameters")

    async with db.session() as data:
        async with data.begin():
            try:
                # First validate and get the release info
                release = await release_delete_validate(data, release_name, session.uid)
                project_name = release.project.name
                version = release.version

                # Delete all associated packages first
                for package in release.packages:
                    await data.delete(package)
                await data.delete(release)

            except routes.FlashError as e:
                logging.exception("FlashError:")
                return await session.redirect(candidate.vote, error=str(e))

    release_dir = util.get_release_candidate_dir() / project_name / version
    if await aiofiles.os.path.exists(release_dir):
        await aioshutil.rmtree(release_dir)
    return await session.redirect(candidate.vote, success="Release deleted successfully")


@routes.committer("/release/bulk/<int:task_id>", methods=["GET"])
async def release_bulk_status(session: routes.CommitterSession, task_id: int) -> str | response.Response:
    """Show status for a bulk download task."""
    async with db.session() as data:
        # Query for the task with the given ID
        task = await data.task(id=task_id).get()
        if not task:
            return await session.redirect(candidate.vote, error=f"Task with ID {task_id} not found.")

        # Verify this is a bulk download task
        if task.task_type != "package_bulk_download":
            return await session.redirect(candidate.vote, error=f"Task with ID {task_id} is not a bulk download task.")

        # If result is a list or tuple with a single item, extract it
        if isinstance(task.result, list | tuple) and (len(task.result) == 1):
            task.result = task.result[0]

        # Get the release associated with this task if available
        release = None
        # Debug print the task.task_args using the logger
        logging.debug(f"Task args: {task.task_args}")
        if task.task_args and isinstance(task.task_args, dict) and ("release_name" in task.task_args):
            release = await data.release(name=task.task_args["release_name"], _committee=True).get()

            # Check whether the user has permission to view this task
            # Either they're a PMC member or committer for the release's PMC
            if release and release.committee:
                if (session.uid not in release.committee.committee_members) and (
                    session.uid not in release.committee.committers
                ):
                    return await session.redirect(candidate.vote, error="You don't have permission to view this task.")

    return await quart.render_template("release-bulk.html", task=task, release=release, TaskStatus=models.TaskStatus)
