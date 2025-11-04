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

import atr.blueprints.post as post
import atr.db.interaction as interaction
import atr.forms as forms
import atr.get as get
import atr.models.sql as sql
import atr.shared as shared
import atr.storage as storage
import atr.tabulate as tabulate
import atr.template as template
import atr.util as util
import atr.web as web


@post.committer("/resolve/manual/<project_name>/<version_name>")
async def manual_selected_post(
    session: web.Committer, project_name: str, version_name: str
) -> web.WerkzeugResponse | str:
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
    resolve_form = await shared.resolve.ResolveVoteManualForm.create_form()
    if not (await resolve_form.validate_on_submit()):
        return await session.redirect(
            get.resolve.manual_selected,
            project_name=project_name,
            version_name=version_name,
            error="Invalid form submission.",
        )
    vote_result = util.unwrap(resolve_form.vote_result.data)
    vote_thread_url = util.unwrap(resolve_form.vote_thread_url.data)
    vote_result_url = util.unwrap(resolve_form.vote_result_url.data)
    await _committees_check(vote_thread_url, vote_result_url)

    async with storage.write_as_project_committee_member(project_name) as wacm:
        success_message = await wacm.vote.resolve_manually(project_name, release, vote_result)
    if vote_result == "passed":
        destination = get.finish.selected
    else:
        destination = get.compose.selected

    return await session.redirect(
        destination, project_name=project_name, version_name=version_name, success=success_message
    )


@post.committer("/resolve/submit/<project_name>/<version_name>")
async def submit_selected(session: web.Committer, project_name: str, version_name: str) -> web.WerkzeugResponse | str:
    """Resolve a vote."""
    await session.check_access(project_name)

    resolve_form = await shared.resolve.ResolveVoteForm.create_form()
    if not (await resolve_form.validate_on_submit()):
        # TODO: Render the page again with errors
        return await session.redirect(
            get.vote.selected,
            project_name=project_name,
            version_name=version_name,
            error="Invalid form submission.",
        )
    email_body = util.unwrap(resolve_form.email_body.data)
    vote_result = util.unwrap(resolve_form.vote_result.data)

    async with storage.write_as_project_committee_member(project_name) as wacm:
        _release, voting_round, success_message, error_message = await wacm.vote.resolve(
            project_name,
            version_name,
            vote_result,
            session.fullname,
            email_body,
        )
    if error_message is not None:
        await quart.flash(error_message, "error")
    if vote_result == "passed":
        if voting_round == 1:
            destination = get.vote.selected
        else:
            destination = get.finish.selected
    else:
        destination = get.compose.selected

    return await session.redirect(
        destination, project_name=project_name, version_name=version_name, success=success_message
    )


@post.committer("/resolve/tabulated/<project_name>/<version_name>")
async def tabulated_selected_post(session: web.Committer, project_name: str, version_name: str) -> str:
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

    submit_form = await forms.Submit.create_form()
    details = None
    committee = None
    thread_id = None
    archive_url = None
    fetch_error = None
    if await submit_form.validate_on_submit():
        latest_vote_task = await interaction.release_latest_vote_task(release)
        if latest_vote_task is not None:
            task_mid = interaction.task_mid_get(latest_vote_task)
            if task_mid:
                async with storage.write(session) as write:
                    wagp = write.as_general_public()
                    archive_url = await wagp.cache.get_message_archive_url(task_mid)

        if archive_url:
            thread_id = archive_url.split("/")[-1]
            if thread_id:
                try:
                    committee = await tabulate.vote_committee(thread_id, release)
                except util.FetchError as e:
                    fetch_error = f"Failed to fetch thread metadata: {e}"
                else:
                    details = await tabulate.vote_details(committee, thread_id, release)
            else:
                fetch_error = "The vote thread could not yet be found."
        else:
            fetch_error = "The vote thread could not yet be found."
    resolve_form = await shared.resolve.ResolveVoteForm.create_form()
    if (committee is None) or (details is None) or (thread_id is None):
        resolve_form.email_body.render_kw = {"rows": 12}
    else:
        resolve_form.email_body.data = tabulate.vote_resolution(
            committee,
            release,
            details.votes,
            details.summary,
            details.passed,
            details.outcome,
            full_name,
            asf_uid,
            thread_id,
        )
        resolve_form.vote_result.data = "passed" if details.passed else "failed"
    return await template.render(
        "resolve-tabulated.html",
        release=release,
        tabulated_votes=details.votes if details is not None else {},
        summary=details.summary if details is not None else {},
        outcome=details.outcome if details is not None else "",
        resolve_form=resolve_form,
        fetch_error=fetch_error,
        archive_url=archive_url,
    )


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
