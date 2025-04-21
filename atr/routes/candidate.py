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

"""candidate.py"""

import json
import logging

import aiofiles.os
import aioshutil
import asfquart
import asfquart.base as base
import httpx
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.mail as mail
import atr.revision as revision
import atr.routes as routes
import atr.routes.preview as preview
import atr.util as util

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")


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


@routes.committer("/candidate/delete", methods=["POST"])
async def delete(session: routes.CommitterSession) -> response.Response:
    """Delete a release candidate."""
    return await session.redirect(resolve, error="Not yet implemented")


@routes.committer("/candidate/resolve", methods=["GET", "POST"], measure_performance=False)
async def resolve(session: routes.CommitterSession) -> response.Response | str:
    """Resolve the vote on a release candidate."""
    # For GET requests, show the list of candidates with ongoing votes
    if quart.request.method == "GET":
        return await _resolve_get(session)
    # For POST requests, process the form
    return await _resolve_post(session)


@routes.committer("/candidate/view/<project_name>/<version_name>")
async def view(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """View all the files in the rsync upload directory for a release."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        return await session.redirect(resolve, error="You do not have access to this project")

    # Check that the release exists
    async with db.session() as data:
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

    # Convert async generator to list
    file_stats = [
        stat async for stat in util.content_list(util.get_release_candidate_dir(), project_name, version_name)
    ]
    logging.warning(f"File stats: {file_stats}")

    return await quart.render_template(
        "phase-view.html",
        file_stats=file_stats,
        release=release,
        format_datetime=routes.format_datetime,
        format_file_size=routes.format_file_size,
        format_permissions=routes.format_permissions,
        phase="release candidate",
        phase_key="candidate",
    )


@routes.committer("/candidate/view/<project_name>/<version_name>/<path:file_path>")
async def view_path(
    session: routes.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response | str:
    """View the content of a specific file in the release candidate."""
    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        return await session.redirect(
            view, error="You do not have access to this project", project_name=project_name, version_name=version_name
        )

    async with db.session() as data:
        release = await data.release(name=models.release_name(project_name, version_name), _project=True).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )

    _max_view_size = 1 * 1024 * 1024
    full_path = util.get_release_candidate_dir() / project_name / version_name / file_path
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
        phase_key="candidate",
    )


# TODO: Move this to draft.py
@routes.committer("/candidate/vote/preview", methods=["POST"])
async def vote_preview(session: routes.CommitterSession) -> quart.wrappers.response.Response | response.Response | str:
    """Show the vote email preview for a release."""

    class VotePreviewForm(util.QuartFormTyped):
        body = wtforms.TextAreaField("Body", validators=[wtforms.validators.InputRequired("Body is required")])
        asfuid = wtforms.StringField("ASF ID", validators=[wtforms.validators.InputRequired("ASF ID is required")])
        # TODO: Validate the vote duration again? Probably not necessary in a preview
        # Note that tasks/vote.py does not use this form
        vote_duration = wtforms.IntegerField(
            "Vote duration", validators=[wtforms.validators.InputRequired("Vote duration is required")]
        )

    form = await VotePreviewForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        return await session.redirect(resolve, error="Invalid form data")

    body = await mail.generate_preview(
        util.unwrap(form.body.data), util.unwrap(form.asfuid.data), util.unwrap(form.vote_duration.data)
    )
    return quart.Response(body, mimetype="text/plain")


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


async def _resolve_get(session: routes.CommitterSession) -> str:
    async with db.session() as data:
        # Get all RELEASE_CANDIDATE_DURING_VOTE releases
        releases = await data.release(
            stage=models.ReleaseStage.RELEASE_CANDIDATE,
            phase=models.ReleasePhase.RELEASE_CANDIDATE_DURING_VOTE,
            _committee=True,
            _project=True,
            _tasks=True,
        ).all()
    user_candidates = session.only_user_releases(releases)

    # Create a unique form for each candidate and find the latest vote initiation task
    candidate_forms = {}
    candidate_vote_tasks = {}
    for candidate in user_candidates:
        form = await ResolveForm.create_form()
        candidate_forms[candidate.name] = form

        # Find the most recent VOTE_INITIATE task for this release
        # TODO: Make this a proper query
        latest_vote_task = None
        task_mid = None
        archive_url = None
        for task in sorted(candidate.tasks, key=lambda t: t.added, reverse=True):
            if task.task_type == models.TaskType.VOTE_INITIATE:
                latest_vote_task = task
                break

        if latest_vote_task and (latest_vote_task.status == models.TaskStatus.COMPLETED) and latest_vote_task.result:
            task_mid = _task_mid(latest_vote_task)
            archive_url = await _task_archive_url(task_mid)
        candidate_vote_tasks[candidate.name] = (latest_vote_task, task_mid, archive_url)

    return await quart.render_template(
        "candidate-resolve.html",
        candidates=user_candidates,
        candidate_forms=candidate_forms,
        candidate_vote_tasks=candidate_vote_tasks,
        format_artifact_name=_format_artifact_name,
    )


async def _resolve_post(session: routes.CommitterSession) -> response.Response:
    form = await ResolveForm.create_form(data=await quart.request.form)
    if not await form.validate_on_submit():
        for _field, errors in form.errors.items():
            for error in errors:
                await quart.flash(f"{error}", "error")
        return await session.redirect(resolve)

    candidate_name = form.candidate_name.data
    vote_result = form.vote_result.data

    if not candidate_name:
        return await session.redirect(resolve, error="Missing candidate name")

    # Extract project name
    try:
        project_name = candidate_name.rsplit("-", 1)[0]
    except ValueError:
        return await session.redirect(resolve, error="Invalid candidate name format")

    # Check that the user has access to the project
    if not any((p.name == project_name) for p in (await session.user_projects)):
        return await session.redirect(resolve, error="You do not have access to this project")

    # Update release status in the database
    async with db.session() as data:
        async with data.begin():
            release = await data.release(name=candidate_name, _project=True).demand(
                routes.FlashError("Release candidate not found")
            )

            # Verify that it's in the correct phase
            if release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DURING_VOTE:
                return await session.redirect(resolve, error="This release is not in the voting phase")

            # Update the release phase based on vote result
            if vote_result == "passed":
                release.stage = models.ReleaseStage.RELEASE
                release.phase = models.ReleasePhase.RELEASE_PREVIEW
                success_message = "Vote marked as passed"
            else:
                release.phase = models.ReleasePhase.RELEASE_CANDIDATE_DRAFT
                success_message = "Vote marked as failed"

            # # Create a task for vote resolution notification
            # task = models.Task(
            #     status=models.TaskStatus.QUEUED,
            #     task_type="vote_resolve",
            #     task_args=[
            #         candidate_name,
            #         vote_result,
            #         session.uid,
            #     ],
            # )
            # data.add(task)

            await data.commit()

    await _resolve_post_files(project_name, release, vote_result, session.uid)
    return await session.redirect(preview.previews, success=success_message)


async def _resolve_post_files(project_name: str, release: models.Release, vote_result: str, asf_uid: str) -> None:
    # TODO: Obtain a lock for this
    source = str(util.get_release_candidate_dir() / project_name / release.version)
    if vote_result == "passed":
        # The vote passed, so promote the release candidate to the release preview directory
        target = str(util.get_release_preview_dir() / project_name / release.version)
        if await aiofiles.os.path.exists(target):
            raise base.ASFQuartException("Release already exists", errorcode=400)
        await aioshutil.move(source, target)
        return

    # The vote failed, so move the release candidate to the release draft directory
    async with revision.create_and_manage(project_name, release.version, asf_uid) as (
        new_revision_dir,
        _new_revision_name,
    ):
        await aioshutil.move(source, new_revision_dir)


async def _task_archive_url(task_mid: str) -> str | None:
    # TODO: Should cache the result of this function in sqlite
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
        return "https://lists.apache.org/thread/" + email_data["mid"]
    except Exception:
        logging.exception("Failed to get archive URL for task %s", task_mid)
        return None


def _task_mid(latest_vote_task: models.Task) -> str:
    task_mid = "(no result)"

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
