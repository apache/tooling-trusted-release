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
import pathlib

import quart
import werkzeug.wrappers.response as response

import asfquart
import asfquart.auth as auth
import asfquart.base as base
import asfquart.session as session
import atr.db as db
import atr.db.models as models
import atr.db.service as service
import atr.routes as routes
import atr.util as util

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")


# Release functions


async def release_delete_validate(data: db.Session, release_key: str, session_uid: str) -> models.Release:
    """Validate release deletion request and return the release if valid."""
    release = await data.release(storage_key=release_key, _committee=True).demand(
        routes.FlashError("Release not found")
    )

    # Check permissions
    if release.committee:
        if (session_uid not in release.committee.committee_members) and (
            session_uid not in release.committee.committers
        ):
            raise routes.FlashError("You don't have permission to delete this release")

    return release


async def release_files_delete(release: models.Release, uploads_path: pathlib.Path) -> None:
    """Delete all files associated with a release."""
    if not release.packages:
        return

    for package in release.packages:
        await routes.package_files_delete(package, uploads_path)


@routes.app_route("/release/delete", methods=["POST"])
@auth.require(auth.Requirements.committer)
async def root_release_delete() -> response.Response:
    """Delete a release and all its associated packages."""
    web_session = await session.read()
    if (web_session is None) or (web_session.uid is None):
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    form = await routes.get_form(quart.request)
    release_key = form.get("release_key")

    if not release_key:
        await quart.flash("Missing required parameters", "error")
        return quart.redirect(quart.url_for("root_candidate_review"))

    async with db.session() as data:
        async with data.begin():
            try:
                release = await release_delete_validate(data, release_key, web_session.uid)
                await release_files_delete(release, pathlib.Path(util.get_release_storage_dir()))
                await data.delete(release)
            except routes.FlashError as e:
                logging.exception("FlashError:")
                await quart.flash(str(e), "error")
                return quart.redirect(quart.url_for("root_candidate_review"))
            except Exception as e:
                await quart.flash(f"Error deleting release: {e!s}", "error")
                return quart.redirect(quart.url_for("root_candidate_review"))

    await quart.flash("Release deleted successfully", "success")
    return quart.redirect(quart.url_for("root_candidate_review"))


@routes.app_route("/release/bulk/<int:task_id>", methods=["GET"])
async def release_bulk_status(task_id: int) -> str | response.Response:
    """Show status for a bulk download task."""
    web_session = await session.read()
    if (web_session is None) or (web_session.uid is None):
        await quart.flash("You must be logged in to view bulk download status.", "error")
        return quart.redirect(quart.url_for("root_login"))

    async with db.session() as data:
        # Query for the task with the given ID
        task = await data.task(id=task_id).get()
        if not task:
            await quart.flash(f"Task with ID {task_id} not found.", "error")
            return quart.redirect(quart.url_for("root_candidate_review"))

        # Verify this is a bulk download task
        if task.task_type != "package_bulk_download":
            await quart.flash(f"Task with ID {task_id} is not a bulk download task.", "error")
            return quart.redirect(quart.url_for("root_candidate_review"))

        # If result is a list or tuple with a single item, extract it
        if isinstance(task.result, list | tuple) and (len(task.result) == 1):
            task.result = task.result[0]

        # Get the release associated with this task if available
        release = None
        # Debug print the task.task_args using the logger
        logging.debug(f"Task args: {task.task_args}")
        if task.task_args and isinstance(task.task_args, dict) and ("release_key" in task.task_args):
            release = await data.release(storage_key=task.task_args["release_key"], _committee=True).get()

            # Check whether the user has permission to view this task
            # Either they're a PMC member or committer for the release's PMC
            if release and release.committee:
                if (web_session.uid not in release.committee.committee_members) and (
                    web_session.uid not in release.committee.committers
                ):
                    await quart.flash("You don't have permission to view this task.", "error")
                    return quart.redirect(quart.url_for("root_candidate_review"))

    return await quart.render_template("release-bulk.html", task=task, release=release, TaskStatus=models.TaskStatus)


@routes.app_route("/release/vote", methods=["GET", "POST"])
@auth.require(auth.Requirements.committer)
async def root_release_vote() -> response.Response | str:
    """Show the vote initiation form for a release."""

    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    release_key = quart.request.args.get("release_key", "")
    form = None
    if quart.request.method == "POST":
        form = await routes.get_form(quart.request)
        release_key = form.get("release_key", "")

    if not release_key:
        await quart.flash("No release key provided", "error")
        return quart.redirect(quart.url_for("root_candidate_review"))

    release = await service.get_release_by_key(release_key)
    if release is None:
        await quart.flash(f"Release with key {release_key} not found", "error")
        return quart.redirect(quart.url_for("root_candidate_review"))

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
                release_key,
                email_to,
                vote_duration,
                gpg_key_id,
                commit_hash,
                web_session.uid,
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
            return quart.redirect(quart.url_for("root_candidate_review"))

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
