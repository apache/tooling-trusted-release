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
import asfquart.base as base
import quart
import werkzeug.wrappers.response as response

import atr.db as db
import atr.db.models as models
import atr.db.service as service
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
        await quart.flash("Missing required parameters", "error")
        return quart.redirect(util.as_url(candidate.review))

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
                await quart.flash(str(e), "error")
                return quart.redirect(util.as_url(candidate.review))

    release_dir = util.get_candidate_draft_dir() / project_name / version
    if await aiofiles.os.path.exists(release_dir):
        await aioshutil.rmtree(release_dir)
    await quart.flash("Release deleted successfully", "success")
    return quart.redirect(util.as_url(candidate.review))


@routes.committer("/release/bulk/<int:task_id>", methods=["GET"])
async def release_bulk_status(session: routes.CommitterSession, task_id: int) -> str | response.Response:
    """Show status for a bulk download task."""
    async with db.session() as data:
        # Query for the task with the given ID
        task = await data.task(id=task_id).get()
        if not task:
            await quart.flash(f"Task with ID {task_id} not found.", "error")
            return quart.redirect(util.as_url(candidate.review))

        # Verify this is a bulk download task
        if task.task_type != "package_bulk_download":
            await quart.flash(f"Task with ID {task_id} is not a bulk download task.", "error")
            return quart.redirect(util.as_url(candidate.review))

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
                    await quart.flash("You don't have permission to view this task.", "error")
                    return quart.redirect(util.as_url(candidate.review))

    return await quart.render_template("release-bulk.html", task=task, release=release, TaskStatus=models.TaskStatus)


@routes.committer("/release/vote", methods=["GET", "POST"])
async def vote(session: routes.CommitterSession) -> response.Response | str:
    """Show the vote initiation form for a release."""
    release_name = quart.request.args.get("release_name", "")
    form = None
    if quart.request.method == "POST":
        form = await routes.get_form(quart.request)
        release_name = form.get("release_name", "")

    if not release_name:
        await quart.flash("No release key provided", "error")
        return quart.redirect(util.as_url(candidate.review))

    release = await service.get_release_by_name(release_name)
    if release is None:
        await quart.flash(f"Release with key {release_name} not found", "error")
        return quart.redirect(util.as_url(candidate.review))

    # If POST, process the form and create a vote_initiate task
    if (quart.request.method == "POST") and (form is not None):
        # Extract form data
        mailing_list = form.get("mailing_list", "dev")
        vote_duration = form.get("vote_duration", "72")
        # These fields are just for testing, we'll do something better in the real UI
        gpg_key_id = form.get("gpg_key_id", "")
        commit_hash = form.get("commit_hash", "")
        if release.committee is None:
            raise base.ASFQuartException("Release has no associated committee", errorcode=400)

        # Prepare email recipient
        email_to = f"{mailing_list}@{release.committee.name}.apache.org"

        # Create a task for vote initiation
        task = models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="vote_initiate",
            task_args=[
                release_name,
                email_to,
                vote_duration,
                gpg_key_id,
                commit_hash,
                session.uid,
            ],
        )
        async with db.create_async_db_session() as db_session:
            db_session.add(task)
            # Flush to get the task ID
            await db_session.flush()
            await db_session.commit()

            await quart.flash(
                f"Vote initiation task queued as task #{task.id}. You'll receive an email confirmation when complete.",
                "success",
            )
            return quart.redirect(util.as_url(candidate.review))

    # For GET
    return await quart.render_template(
        "release-vote.html",
        release=release,
        email_preview=generate_vote_email_preview(release),
    )


def generate_vote_email_preview(release: models.Release) -> str:
    """Generate a preview of the vote email."""
    version = release.version

    # Get PMC details
    if release.committee is None:
        raise base.ASFQuartException("Release has no associated committee", errorcode=400)
    committee_name = release.committee.name
    committee_display = release.committee.display_name

    # Get project information
    project_name = release.project.name if release.project else "Unknown"

    # Create email subject
    subject = f"[VOTE] Release Apache {committee_display} {project_name} {version}"

    # Create email body
    body = f"""Hello {committee_name},

I'd like to call a vote on releasing the following artifacts as
Apache {committee_display} {project_name} {version}.

The release candidate can be found at:

https://apache.example.org/{committee_name}/{project_name}-{version}/

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
