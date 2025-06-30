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

import quart
import sqlmodel
import werkzeug.wrappers.response as response

import atr.construct as construct
import atr.db as db
import atr.db.models as models
import atr.revision as revision
import atr.routes as routes
import atr.routes.compose as compose
import atr.routes.finish as finish
import atr.routes.vote as vote
import atr.routes.voting as voting
import atr.tasks.message as message
import atr.util as util


async def release_latest_vote_task(release: models.Release) -> models.Task | None:
    """Find the most recent VOTE_INITIATE task for this release."""
    via = models.validate_instrumented_attribute
    async with db.session() as data:
        query = (
            sqlmodel.select(models.Task)
            .where(models.Task.project_name == release.project_name)
            .where(models.Task.version_name == release.version)
            .where(models.Task.task_type == models.TaskType.VOTE_INITIATE)
            .where(via(models.Task.status).notin_([models.TaskStatus.QUEUED, models.TaskStatus.ACTIVE]))
            .where(via(models.Task.result).is_not(None))
            .order_by(via(models.Task.added).desc())
            .limit(1)
        )
        task = (await data.execute(query)).scalar_one_or_none()
        return task


@routes.committer("/resolve/<project_name>/<version_name>", methods=["POST"])
async def selected_post(
    session: routes.CommitterSession, project_name: str, version_name: str
) -> response.Response | str:
    """Resolve a vote."""
    await session.check_access(project_name)

    release = await session.release(
        project_name,
        version_name,
        with_project=True,
        with_committee=True,
        phase=models.ReleasePhase.RELEASE_CANDIDATE,
    )

    is_podling = False
    if release.project.committee is not None:
        is_podling = release.project.committee.is_podling
    podling_thread_id = release.podling_thread_id

    latest_vote_task = await release_latest_vote_task(release)
    if latest_vote_task is None:
        return "No vote task found, unable to send resolution message."
    resolve_form = await vote.ResolveVoteForm.create_form()
    if not resolve_form.validate_on_submit():
        # TODO: Render the page again with errors
        return await session.redirect(
            vote.selected_resolve,
            project_name=project_name,
            version_name=version_name,
            error="Invalid form submission.",
        )
    email_body = util.unwrap(resolve_form.email_body.data)
    vote_result = util.unwrap(resolve_form.vote_result.data)
    first_podling_round_passing = is_podling and (podling_thread_id is None) and (vote_result == "passed")
    release, success_message = await _resolve_vote(
        session,
        project_name,
        vote_result,
        email_body,
        latest_vote_task,
        release,
        first_podling_round_passing,
    )
    if first_podling_round_passing:
        destination = vote.selected
    elif vote_result == "passed":
        destination = finish.selected
    else:
        destination = compose.selected
    return await session.redirect(
        destination, project_name=project_name, version_name=version_name, success=success_message
    )


def task_mid_get(latest_vote_task: models.Task) -> str | None:
    if util.is_dev_environment():
        return vote.TEST_MID
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


async def _resolve_vote(
    session: routes.CommitterSession,
    project_name: str,
    vote_result: str,
    resolution_body: str,
    latest_vote_task: models.Task,
    release: models.Release,
    first_podling_round_passing: bool,
) -> tuple[models.Release, str]:
    # Check that the user has access to the project
    await session.check_access(project_name)

    # Update release status in the database
    async with db.session() as data:
        async with data.begin():
            # Attach the existing release to the session
            release = await data.merge(release)
            # Update the release phase based on vote result
            if first_podling_round_passing:
                # This is the first podling vote, by the PPMC and not the Incubator PMC
                # In this branch, we do not move to RELEASE_PREVIEW but keep everything the same
                # We only set the podling_thread_id to the thread_id of the vote thread
                # Then we automatically start the Incubator PMC vote
                # TODO: Note on the resolve vote page that resolving the Project PPMC vote starts the Incubator PMC vote
                task_mid = task_mid_get(latest_vote_task)
                archive_url = await vote.task_archive_url_cached(task_mid)
                if archive_url is None:
                    await quart.flash("No archive URL found for podling vote", "error")
                    return release, "Failure"
                thread_id = archive_url.split("/")[-1]
                release.podling_thread_id = thread_id
                # incubator_vote_address = "general@incubator.apache.org"
                incubator_vote_address = "user-test@tooling.apache.org"
                if not release.project.committee:
                    raise ValueError("Project has no committee")
                revision_number = release.latest_revision_number
                if revision_number is None:
                    raise ValueError("Release has no revision number")
                await voting.start_vote(
                    committee=release.project.committee,
                    email_to=incubator_vote_address,
                    permitted_recipients=[incubator_vote_address],
                    project_name=release.project.name,
                    version_name=release.version,
                    selected_revision_number=revision_number,
                    session=session,
                    vote_duration_choice=latest_vote_task.task_args["vote_duration"],
                    subject_data=f"[VOTE] Release {release.project.display_name} {release.version}",
                    body_data=await construct.start_vote_default(release.project.name),
                    data=data,
                    release=release,
                    promote=False,
                )
                success_message = "Project PPMC vote marked as passed, and Incubator PMC vote automatically started"
            elif vote_result == "passed":
                release.phase = models.ReleasePhase.RELEASE_PREVIEW
                success_message = "Vote marked as passed"

                description = "Create a preview revision from the last candidate draft"
                async with revision.create_and_manage(
                    project_name, release.version, session.uid, description=description
                ) as _creating:
                    pass
            else:
                release.phase = models.ReleasePhase.RELEASE_CANDIDATE_DRAFT
                success_message = "Vote marked as failed"

    error_message = await _send_resolution(session, release, vote_result, resolution_body)
    if error_message is not None:
        await quart.flash(error_message, "error")
    return release, success_message


async def _send_resolution(
    session: routes.CommitterSession,
    release: models.Release,
    resolution: str,
    body: str,
) -> str | None:
    # Get the email thread
    latest_vote_task = await release_latest_vote_task(release)
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
        project_name=release.project.name,
        version_name=release.version,
    )
    async with db.session() as data:
        data.add(task)
        await data.flush()
        await data.commit()
    return None
