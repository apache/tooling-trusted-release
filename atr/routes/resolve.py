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


import quart
import sqlmodel
import werkzeug.wrappers.response as response
import wtforms

import atr.construct as construct
import atr.db as db
import atr.models.results as results
import atr.models.sql as sql
import atr.revision as revision
import atr.routes as routes
import atr.routes.compose as compose
import atr.routes.finish as finish
import atr.routes.vote as vote
import atr.routes.voting as voting
import atr.tabulate as tabulate
import atr.tasks.message as message
import atr.template as template
import atr.util as util


class ResolveVoteForm(util.QuartFormTyped):
    """Form for resolving a vote."""

    email_body = wtforms.TextAreaField("Email body", render_kw={"rows": 24})
    vote_result = wtforms.RadioField(
        "Vote result",
        choices=[("passed", "Passed"), ("failed", "Failed")],
        validators=[wtforms.validators.InputRequired("Vote result is required")],
    )
    submit = wtforms.SubmitField("Resolve vote")


class ResolveVoteManualForm(util.QuartFormTyped):
    """Form for resolving a vote manually."""

    vote_result = wtforms.RadioField(
        "Vote result",
        choices=[("passed", "Passed"), ("failed", "Failed")],
        validators=[wtforms.validators.InputRequired("Vote result is required")],
    )
    vote_thread_url = wtforms.StringField("Vote thread URL")
    vote_result_url = wtforms.StringField("Vote result URL")
    submit = wtforms.SubmitField("Resolve vote")


async def release_latest_vote_task(release: sql.Release) -> sql.Task | None:
    """Find the most recent VOTE_INITIATE task for this release."""
    via = sql.validate_instrumented_attribute
    async with db.session() as data:
        query = (
            sqlmodel.select(sql.Task)
            .where(sql.Task.project_name == release.project_name)
            .where(sql.Task.version_name == release.version)
            .where(sql.Task.task_type == sql.TaskType.VOTE_INITIATE)
            .where(via(sql.Task.status).notin_([sql.TaskStatus.QUEUED, sql.TaskStatus.ACTIVE]))
            .where(via(sql.Task.result).is_not(None))
            .order_by(via(sql.Task.added).desc())
            .limit(1)
        )
        task = (await data.execute(query)).scalar_one_or_none()
        return task


@routes.committer("/resolve/manual/<project_name>/<version_name>")
async def manual_selected(session: routes.CommitterSession, project_name: str, version_name: str) -> str:
    """Get the manual vote resolution page."""
    await session.check_access(project_name)

    release = await session.release(
        project_name,
        version_name,
        phase=sql.ReleasePhase.RELEASE_CANDIDATE,
        with_release_policy=True,
        with_project_release_policy=True,
    )
    if not release.vote_manual:
        raise RuntimeError("This page is for manual votes only")
    resolve_form = await ResolveVoteManualForm.create_form()
    return await template.render(
        "resolve-manual.html",
        release=release,
        resolve_form=resolve_form,
    )


@routes.committer("/resolve/manual/<project_name>/<version_name>", methods=["POST"])
async def manual_selected_post(
    session: routes.CommitterSession, project_name: str, version_name: str
) -> response.Response | str:
    """Post the manual vote resolution page."""
    await session.check_access(project_name)
    release = await session.release(
        project_name,
        version_name,
        phase=sql.ReleasePhase.RELEASE_CANDIDATE,
        with_release_policy=True,
        with_project_release_policy=True,
    )
    if not release.vote_manual:
        raise RuntimeError("This page is for manual votes only")
    resolve_form = await ResolveVoteManualForm.create_form()
    if not resolve_form.validate_on_submit():
        return await session.redirect(
            manual_selected,
            project_name=project_name,
            version_name=version_name,
            error="Invalid form submission.",
        )
    vote_result = util.unwrap(resolve_form.vote_result.data)
    vote_thread_url = util.unwrap(resolve_form.vote_thread_url.data)
    vote_result_url = util.unwrap(resolve_form.vote_result_url.data)
    await _committees_check(vote_thread_url, vote_result_url)

    async with db.session() as data:
        async with data.begin():
            release = await data.merge(release)
            if vote_result == "passed":
                release.phase = sql.ReleasePhase.RELEASE_PREVIEW
                success_message = "Vote marked as passed"
                description = "Create a preview revision from the last candidate draft"
                async with revision.create_and_manage(
                    project_name, release.version, session.uid, description=description
                ) as _creating:
                    pass
            else:
                release.phase = sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
                success_message = "Vote marked as failed"
    if vote_result == "passed":
        destination = finish.selected
    else:
        destination = compose.selected

    return await session.redirect(
        destination, project_name=project_name, version_name=version_name, success=success_message
    )


@routes.committer("/resolve/submit/<project_name>/<version_name>", methods=["POST"])
async def submit_selected(
    session: routes.CommitterSession, project_name: str, version_name: str
) -> response.Response | str:
    """Resolve a vote."""
    await session.check_access(project_name)

    release = await session.release(
        project_name,
        version_name,
        with_project=True,
        with_committee=True,
        phase=sql.ReleasePhase.RELEASE_CANDIDATE,
    )

    is_podling = False
    if release.project.committee is not None:
        is_podling = release.project.committee.is_podling
    podling_thread_id = release.podling_thread_id

    latest_vote_task = await release_latest_vote_task(release)
    if latest_vote_task is None:
        raise RuntimeError("No vote task found, unable to send resolution message.")
    resolve_form = await ResolveVoteForm.create_form()
    if not resolve_form.validate_on_submit():
        # TODO: Render the page again with errors
        return await session.redirect(
            vote.selected,
            project_name=project_name,
            version_name=version_name,
            error="Invalid form submission.",
        )
    email_body = util.unwrap(resolve_form.email_body.data)
    vote_result = util.unwrap(resolve_form.vote_result.data)
    voting_round = None
    if is_podling is True:
        voting_round = 1 if (podling_thread_id is None) else 2
    release, success_message = await _resolve_vote(
        session,
        project_name,
        vote_result,
        email_body,
        latest_vote_task,
        release,
        voting_round,
    )
    if vote_result == "passed":
        if voting_round == 1:
            destination = vote.selected
        else:
            destination = finish.selected
    else:
        destination = compose.selected

    return await session.redirect(
        destination, project_name=project_name, version_name=version_name, success=success_message
    )


@routes.committer("/resolve/tabulated/<project_name>/<version_name>", methods=["POST"])
async def tabulated_selected_post(session: routes.CommitterSession, project_name: str, version_name: str) -> str:
    """Tabulate votes."""
    await session.check_access(project_name)
    asf_uid = session.uid
    full_name = session.fullname

    release = await session.release(
        project_name,
        version_name,
        phase=sql.ReleasePhase.RELEASE_CANDIDATE,
        with_release_policy=True,
        with_project_release_policy=True,
    )
    if release.vote_manual:
        raise RuntimeError("This page is for tabulated votes only")

    hidden_form = await util.HiddenFieldForm.create_form()
    tabulated_votes = None
    summary = None
    passed = None
    outcome = None
    committee = None
    thread_id = None
    archive_url = None
    fetch_error = None
    if await hidden_form.validate_on_submit():
        # TODO: Just pass the thread_id itself instead?
        archive_url = hidden_form.hidden_field.data or ""
        thread_id = archive_url.split("/")[-1]
        if thread_id:
            try:
                committee = await tabulate.vote_committee(thread_id, release)
            except util.FetchError as e:
                fetch_error = f"Failed to fetch thread metadata: {e}"
            else:
                start_unixtime, tabulated_votes = await tabulate.votes(committee, thread_id)
                summary = tabulate.vote_summary(tabulated_votes)
                passed, outcome = tabulate.vote_outcome(release, start_unixtime, tabulated_votes)
        else:
            fetch_error = "The vote thread could not yet be found."
    resolve_form = await ResolveVoteForm.create_form()
    if (
        (committee is None)
        or (tabulated_votes is None)
        or (summary is None)
        or (passed is None)
        or (outcome is None)
        or (thread_id is None)
    ):
        resolve_form.email_body.render_kw = {"rows": 12}
    else:
        resolve_form.email_body.data = tabulate.vote_resolution(
            committee, release, tabulated_votes, summary, passed, outcome, full_name, asf_uid, thread_id
        )
        resolve_form.vote_result.data = "passed" if passed else "failed"
    return await template.render(
        "resolve-tabulated.html",
        release=release,
        tabulated_votes=tabulated_votes,
        summary=summary,
        outcome=outcome,
        resolve_form=resolve_form,
        fetch_error=fetch_error,
        archive_url=archive_url,
    )


def task_mid_get(latest_vote_task: sql.Task) -> str | None:
    if util.is_dev_environment():
        return vote.TEST_MID
    # TODO: Improve this

    result = latest_vote_task.result
    if not isinstance(result, results.VoteInitiate):
        return None
    return result.mid


async def _committees_check(vote_thread_url: str, vote_result_url: str) -> None:
    if not vote_thread_url.startswith("https://lists.apache.org/thread/"):
        raise RuntimeError("Vote thread URL is not a valid Apache email thread URL")
    if not vote_result_url.startswith("https://lists.apache.org/thread/"):
        raise RuntimeError("Vote result URL is not a valid Apache email thread URL")

    vote_thread_id = vote_thread_url.removeprefix("https://lists.apache.org/thread/")
    result_thread_id = vote_result_url.removeprefix("https://lists.apache.org/thread/")

    vote_committee_label = None
    result_committee_label = None
    async for _mid, msg in util.thread_messages(vote_thread_id):
        if "list_raw" in msg:
            list_raw = msg["list_raw"]
            vote_committee_label = list_raw.split(".apache.org", 1)[0].split(".", 1)[-1]
            break

    async for _mid, msg in util.thread_messages(result_thread_id):
        if "list_raw" in msg:
            list_raw = msg["list_raw"]
            result_committee_label = list_raw.split(".apache.org", 1)[0].split(".", 1)[-1]
            break

    if vote_committee_label != result_committee_label:
        raise RuntimeError("Vote committee and result committee do not match")

    if vote_committee_label is None:
        raise RuntimeError("Vote committee not found")
    if result_committee_label is None:
        raise RuntimeError("Result committee not found")


async def _resolve_vote(
    session: routes.CommitterSession,
    project_name: str,
    vote_result: str,
    resolution_body: str,
    latest_vote_task: sql.Task,
    release: sql.Release,
    voting_round: int | None,
) -> tuple[sql.Release, str]:
    # Check that the user has access to the project
    await session.check_access(project_name)

    # Update release status in the database
    async with db.session() as data:
        async with data.begin():
            # Attach the existing release to the session
            release = await data.merge(release)
            # Update the release phase based on vote result
            extra_destination = None
            if (voting_round == 1) and (vote_result == "passed"):
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
                release.phase = sql.ReleasePhase.RELEASE_PREVIEW
                success_message = "Vote marked as passed"

                description = "Create a preview revision from the last candidate draft"
                async with revision.create_and_manage(
                    project_name, release.version, session.uid, description=description
                ) as _creating:
                    pass
                if (voting_round == 2) and (release.podling_thread_id is not None):
                    round_one_email_address, round_one_message_id = await util.email_mid_from_thread_id(
                        release.podling_thread_id
                    )
                    extra_destination = (round_one_email_address, round_one_message_id)
            else:
                release.phase = sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
                success_message = "Vote marked as failed"

    error_message = await _send_resolution(
        session, release, vote_result, resolution_body, extra_destination=extra_destination
    )
    if error_message is not None:
        await quart.flash(error_message, "error")
    return release, success_message


async def _send_resolution(
    session: routes.CommitterSession,
    release: sql.Release,
    resolution: str,
    body: str,
    extra_destination: tuple[str, str] | None = None,
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

    task = sql.Task(
        status=sql.TaskStatus.QUEUED,
        task_type=sql.TaskType.MESSAGE_SEND,
        task_args=message.Send(
            email_sender=email_sender,
            email_recipient=email_recipient,
            subject=subject,
            body=body,
            in_reply_to=in_reply_to,
        ).model_dump(),
        asf_uid=util.unwrap(session.uid),
        project_name=release.project.name,
        version_name=release.version,
    )
    tasks = [task]
    if extra_destination is not None:
        task = sql.Task(
            status=sql.TaskStatus.QUEUED,
            task_type=sql.TaskType.MESSAGE_SEND,
            task_args=message.Send(
                email_sender=email_sender,
                email_recipient=extra_destination[0],
                subject=subject,
                body=body,
                in_reply_to=extra_destination[1],
            ).model_dump(),
            asf_uid=util.unwrap(session.uid),
            project_name=release.project.name,
            version_name=release.version,
        )
        tasks.append(task)
    async with db.session() as data:
        data.add_all(tasks)
        await data.flush()
        await data.commit()
    return None
