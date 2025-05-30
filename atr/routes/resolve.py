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
import os

import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.revision as revision
import atr.routes as routes
import atr.routes.compose as compose
import atr.routes.finish as finish
import atr.routes.vote as vote
import atr.tasks.message as message
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
    resolution_body = wtforms.TextAreaField(
        "Resolution email body",
        validators=[wtforms.validators.Optional()],
        description="Enter optional comment for the resolution email (e.g., summary of issues if failed).",
    )
    submit = wtforms.SubmitField("Resolve vote")


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
        return await session.redirect(vote.selected, project_name=project_name, version_name=version_name)

    candidate_name = form.candidate_name.data
    vote_result = form.vote_result.data
    resolution_body = util.unwrap_type(form.resolution_body.data, str)
    if not candidate_name:
        return await session.redirect(
            vote.selected, error="Missing candidate name", project_name=project_name, version_name=version_name
        )

    # Extract project name
    try:
        project_name, version_name = candidate_name.rsplit("-", 1)
    except ValueError:
        return await session.redirect(
            vote.selected, error="Invalid candidate name format", project_name=project_name, version_name=version_name
        )

    # Check that the user has access to the project
    await session.check_access(project_name)

    # Update release status in the database
    async with db.session() as data:
        async with data.begin():
            release = await session.release(
                project_name,
                version_name,
                with_tasks=True,
                with_project=True,
                phase=models.ReleasePhase.RELEASE_CANDIDATE,
                data=data,
            )

            # Update the release phase based on vote result
            if vote_result == "passed":
                release.phase = models.ReleasePhase.RELEASE_PREVIEW
                success_message = "Vote marked as passed"
                destination = finish.selected
            else:
                release.phase = models.ReleasePhase.RELEASE_CANDIDATE_DRAFT
                success_message = "Vote marked as failed"
                destination = compose.selected

    description = "Create a preview revision from the last candidate draft"
    async with revision.create_and_manage(
        project_name, release.version, session.uid, description=description
    ) as _creating:
        pass

    error_message = await _send_resolution(session, release, vote_result, resolution_body)
    if error_message is not None:
        await quart.flash(error_message, "error")

    return await session.redirect(
        destination, success=success_message, project_name=project_name, version_name=release.version
    )


def task_mid_get(latest_vote_task: models.Task) -> str | None:
    if "LOCAL_DEBUG" in os.environ:
        return "818a44a3-6984-4aba-a650-834e86780b43@apache.org"
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


async def _send_resolution(
    session: routes.CommitterSession,
    release: models.Release,
    resolution: str,
    body: str,
) -> str | None:
    # Get the email thread
    latest_vote_task = release_latest_vote_task(release)
    if latest_vote_task is None:
        return "No vote task found, unable to send resolution message."
    vote_thread_mid = task_mid_get(latest_vote_task)
    if vote_thread_mid is None:
        return "No vote thread found, unable to send resolution message."

    # Construct the reply email
    # original_subject = latest_vote_task.task_args["subject"]

    # Arguments for the task to cast a vote
    email_recipient = latest_vote_task.task_args["email_to"]
    email_sender = f"{session.uid}@apache.org"
    subject = f"[VOTE] [RESULT] Release {release.project.display_name} {release.version} {resolution.upper()}"
    body = f"{body}\n\n-- \n{session.fullname} ({session.uid})"
    in_reply_to = vote_thread_mid

    task = models.Task(
        status=models.TaskStatus.QUEUED,
        task_type=models.TaskType.MESSAGE_SEND,
        task_args=message.Send(
            email_sender=email_sender,
            email_recipient=email_recipient,
            subject=subject,
            body=body,
            in_reply_to=in_reply_to,
        ).model_dump(),
        release_name=release.name,
    )
    async with db.session() as data:
        data.add(task)
        await data.flush()
        await data.commit()
    return None
