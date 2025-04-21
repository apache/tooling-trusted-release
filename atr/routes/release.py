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
import asfquart.base as base
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.routes.draft as draft
import atr.util as util

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")


class StartReleaseForm(util.QuartFormTyped):
    project_name = wtforms.HiddenField()
    version_name = wtforms.StringField(
        "Version",
        validators=[
            wtforms.validators.InputRequired("Version is required"),
            wtforms.validators.Length(min=1, max=100),
        ],
    )
    submit = wtforms.SubmitField("Start new release")


@routes.committer("/release/bulk/<int:task_id>", methods=["GET"])
async def bulk_status(session: routes.CommitterSession, task_id: int) -> str | response.Response:
    """Show status for a bulk download task."""
    async with db.session() as data:
        # Query for the task with the given ID
        task = await data.task(id=task_id).get()
        if not task:
            return await session.redirect(draft.drafts, error=f"Task with ID {task_id} not found.")

        # Verify this is a bulk download task
        if task.task_type != "package_bulk_download":
            return await session.redirect(draft.drafts, error=f"Task with ID {task_id} is not a bulk download task.")

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
                    return await session.redirect(draft.drafts, error="You don't have permission to view this task.")

    return await quart.render_template("release-bulk.html", task=task, release=release, TaskStatus=models.TaskStatus)


@routes.committer("/releases/completed/<project_name>")
async def completed(session: routes.CommitterSession, project_name: str) -> str:
    """View all completed releases for a project."""
    async with db.session() as data:
        project = await data.project(name=project_name).demand(
            base.ASFQuartException(f"Project {project_name} not found", errorcode=404)
        )

        releases = await data.release(
            project_id=project.id,
            phase=models.ReleasePhase.RELEASE,
            _committee=True,
            _packages=True,
        ).all()

    return await quart.render_template(
        "releases-completed.html", releases=releases, format_datetime=routes.format_datetime
    )


@routes.committer("/releases")
async def releases(session: routes.CommitterSession) -> str:
    """View all releases."""
    # Releases are public, so we don't need to filter by user
    async with db.session() as data:
        releases = await data.release(
            stage=models.ReleaseStage.RELEASE,
            phase=models.ReleasePhase.RELEASE,
            _committee=True,
            _packages=True,
        ).all()

    return await quart.render_template(
        "releases.html",
        releases=list(releases),
    )


@routes.committer("/release/select/<project_name>")
async def select(session: routes.CommitterSession, project_name: str) -> str:
    """Show releases in progress for a project."""
    async with db.session() as data:
        project = await data.project(name=project_name, _releases=True).demand(
            base.ASFQuartException(f"Project {project_name} not found", errorcode=404)
        )
        releases = await project.releases_in_progress
        return await quart.render_template(
            "release-select.html", project=project, releases=releases, format_datetime=routes.format_datetime
        )


@routes.committer("/release/start/<project_name>", methods=["GET", "POST"])
async def start(session: routes.CommitterSession, project_name: str) -> response.Response | str:
    """Allow the user to start a new release draft, or handle its submission."""
    async with db.session() as data:
        project = await data.project(name=project_name).demand(
            base.ASFQuartException(f"Project {project_name} not found", errorcode=404)
        )

    form = await StartReleaseForm.create_form(data=await quart.request.form if quart.request.method == "POST" else None)
    if (quart.request.method == "GET") or (not form.project_name.data):
        form.project_name.data = project_name

    if (quart.request.method == "POST") and (await form.validate_on_submit()):
        try:
            # TODO: Move the helper somewhere else
            # We already have the project, so we only need to get [0]
            new_release = (
                await draft.create_release_draft(
                    project_name=str(form.project_name.data), version=str(form.version_name.data), asf_uid=session.uid
                )
            )[0]
            # Redirect to the new draft's overview page on success
            return await session.redirect(
                draft.content,
                project_name=project.name,
                version_name=new_release.version,
                success="Release candidate draft created successfully",
            )
        except (routes.FlashError, base.ASFQuartException) as e:
            # Flash the error and let the code fall through to render the template below
            await quart.flash(str(e), "error")

    # Render the template for GET requests or POST requests with validation errors
    return await quart.render_template("release-start.html", project=project, form=form, routes=routes)


@routes.committer("/release/view/<project_name>/<version_name>")
async def view(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """View all the files in the rsync upload directory for a release."""
    # Releases are public, so we don't need to filter by user

    # Check that the release exists
    async with db.session() as data:
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

    # Convert async generator to list
    file_stats = [stat async for stat in util.content_list(util.get_release_dir(), project_name, version_name)]

    return await quart.render_template(
        "phase-view.html",
        file_stats=file_stats,
        release=release,
        format_datetime=routes.format_datetime,
        format_file_size=routes.format_file_size,
        format_permissions=routes.format_permissions,
        phase="release",
        phase_key="release",
    )


@routes.committer("/release/view/<project_name>/<version_name>/<path:file_path>")
async def view_path(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response | str:
    """View the content of a specific file in the final release."""
    # Releases are public, no specific access check needed here beyond being a committer

    async with db.session() as data:
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

    _max_view_size = 1 * 1024 * 1024
    full_path = util.get_release_dir() / project_name / version_name / file_path
    content, is_text, is_truncated, error_message = await util.read_file_for_viewer(full_path, _max_view_size)
    return await quart.render_template(
        "phase-view-path.html",
        release=release,
        project_name=project_name,
        version_name=version_name,
        file_path=file_path,
        content=content,
        is_text=is_text,
        is_truncated=is_truncated,
        error_message=error_message,
        format_file_size=routes.format_file_size,
        phase_key="release",
    )
