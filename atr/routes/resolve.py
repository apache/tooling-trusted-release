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

import json
import logging
import os

import httpx
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.routes.compose as compose
import atr.routes.finish as finish
import atr.util as util


class ResolveForm(util.QuartFormTyped):
    """Form for resolving a vote on a release candidate."""

    candidate_name = wtforms.StringField(
        "Candidate name", validators=[wtforms.validators.InputRequired("Candidate name is required")]
    )
    vote_result = wtforms.RadioField(
        "Vote result",
        choices=[("passed", "Passed"), ("failed", "Failed")],
        validators=[wtforms.validators.InputRequired("Vote result is required")],
    )
    submit = wtforms.SubmitField("Resolve vote")


@routes.committer("/resolve/<project_name>/<version_name>", measure_performance=False)
async def selected(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Resolve the vote on a release candidate."""
    await session.check_access(project_name)

    release = await session.release(
        project_name,
        version_name,
        phase=models.ReleasePhase.RELEASE_CANDIDATE,
        with_committee=True,
        with_tasks=True,
    )

    form = await ResolveForm.create_form()

    latest_vote_task = release_latest_vote_task(release)
    task_mid = None
    archive_url = None
    if latest_vote_task is not None:
        task_mid = task_mid_get(latest_vote_task)
        archive_url = await _task_archive_url_cached(task_mid)

    if ("LOCAL_DEBUG" in os.environ) and (latest_vote_task is not None):
        latest_vote_task.status = models.TaskStatus.COMPLETED
        latest_vote_task.result = [json.dumps({"mid": "818a44a3-6984-4aba-a650-834e86780b43@apache.org"})]

    return await quart.render_template(
        "candidate-resolve-release.html",
        release=release,
        format_artifact_name=_format_artifact_name,
        form=form,
        format_datetime=routes.format_datetime,
        vote_task=latest_vote_task,
        task_mid=task_mid,
        archive_url=archive_url,
    )


@routes.committer("/resolve/<project_name>/<version_name>", methods=["POST"], measure_performance=False)
async def selected_post(
    session: routes.CommitterSession, project_name: str, version_name: str
) -> response.Response | str:
    """Resolve the vote on a release candidate."""
    await session.check_access(project_name)

    form = await ResolveForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        for _field, errors in form.errors.items():
            for error in errors:
                await quart.flash(f"{error}", "error")
        return await session.redirect(selected, project_name=project_name, version_name=version_name)

    candidate_name = form.candidate_name.data
    vote_result = form.vote_result.data

    if not candidate_name:
        return await session.redirect(
            selected, error="Missing candidate name", project_name=project_name, version_name=version_name
        )

    # Extract project name
    try:
        project_name, version_name = candidate_name.rsplit("-", 1)
    except ValueError:
        return await session.redirect(
            selected, error="Invalid candidate name format", project_name=project_name, version_name=version_name
        )

    # Check that the user has access to the project
    await session.check_access(project_name)

    # Update release status in the database
    async with db.session() as data:
        async with data.begin():
            release = await session.release(
                project_name, version_name, phase=models.ReleasePhase.RELEASE_CANDIDATE, data=data
            )

            # Update the release phase based on vote result
            if vote_result == "passed":
                release.stage = models.ReleaseStage.RELEASE
                release.phase = models.ReleasePhase.RELEASE_PREVIEW
                success_message = "Vote marked as passed"
                destination = finish.selected
            else:
                release.phase = models.ReleasePhase.RELEASE_CANDIDATE_DRAFT
                success_message = "Vote marked as failed"
                destination = compose.selected

    return await session.redirect(
        destination, success=success_message, project_name=project_name, version_name=release.version
    )


def _format_artifact_name(project_name: str, version: str, is_podling: bool = False) -> str:
    """Format an artifact name according to Apache naming conventions.

    For regular projects: apache-${project}-${version}
    For podlings: apache-${project}-incubating-${version}
    """
    # TODO: Format this better based on committee and project
    # Must depend on whether project is a subproject or not
    if is_podling:
        return f"apache-{project_name}-incubating-{version}"
    return f"apache-{project_name}-{version}"


def release_latest_vote_task(release: models.Release) -> models.Task | None:
    # Find the most recent VOTE_INITIATE task for this release
    # TODO: Make this a proper query
    for task in sorted(release.tasks, key=lambda t: t.added, reverse=True):
        if task.task_type != models.TaskType.VOTE_INITIATE:
            continue
        # if task.status != models.TaskStatus.COMPLETED:
        #     continue
        if (task.status == models.TaskStatus.QUEUED) or (task.status == models.TaskStatus.ACTIVE):
            continue
        if task.result is None:
            continue
        return task
    return None


async def _task_archive_url(task_mid: str) -> str | None:
    if "@" not in task_mid:
        return None

    # TODO: This List ID will be dynamic when we allow posting to arbitrary lists
    lid = "user-tests.tooling.apache.org"
    url = f"https://lists.apache.org/api/email.lua?id=%3C{task_mid}%3E&listid=%3C{lid}%3E"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
        response.raise_for_status()
        email_data = response.json()
        mid = email_data["mid"]
        if not isinstance(mid, str):
            return None
        return "https://lists.apache.org/thread/" + mid
    except Exception:
        logging.exception("Failed to get archive URL for task %s", task_mid)
        return None


async def _task_archive_url_cached(task_mid: str | None) -> str | None:
    if "LOCAL_DEBUG" in os.environ:
        return "https://lists.apache.org/thread/619hn4x796mh3hkk3kxg1xnl48dy2s64"
    if task_mid is None:
        return None
    if "@" not in task_mid:
        return None

    async with db.session() as data:
        url = await data.ns_text_get(
            "mid-url-cache",
            task_mid,
        )
        if url is not None:
            return url

    url = await _task_archive_url(task_mid)
    if url is not None:
        await data.ns_text_set(
            "mid-url-cache",
            task_mid,
            url,
        )

    return url


def task_mid_get(latest_vote_task: models.Task) -> str | None:
    # TODO: Improve this
    task_mid = None

    try:
        for result in latest_vote_task.result or []:
            if isinstance(result, str):
                parsed_result = json.loads(result)
            else:
                # Shouldn't happen
                parsed_result = result
            if isinstance(parsed_result, dict):
                task_mid = parsed_result.get("mid", "(mid not found in result)")
                break
            else:
                task_mid = "(malformed result)"

    except (json.JSONDecodeError, TypeError):
        task_mid = "(malformed result)"

    return task_mid
