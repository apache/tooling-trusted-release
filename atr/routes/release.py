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

import asfquart
import quart
import werkzeug.wrappers.response as response

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.routes.candidate as candidate

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")


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


@routes.committer("/release/review")
async def review(session: routes.CommitterSession) -> str:
    """Show all releases."""
    # Releases are public, so we don't need to filter by user
    # TODO: Add RELEASE_BEFORE_ANNOUNCEMENT releases?
    async with db.session() as data:
        releases = await data.release(
            stage=models.ReleaseStage.RELEASE,
            phase=models.ReleasePhase.RELEASE_AFTER_ANNOUNCEMENT,
            _committee=True,
            _packages=True,
        ).all()

    return await quart.render_template(
        "release-review.html",
        releases=releases,
    )
