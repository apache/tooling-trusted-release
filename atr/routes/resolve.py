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


import asfquart.base as base
import quart
import werkzeug.wrappers.response as response

import atr.forms as forms
import atr.get.compose as compose
import atr.get.vote as vote
import atr.models.sql as sql
import atr.route as route
import atr.routes.finish as finish
import atr.storage as storage
import atr.tabulate as tabulate
import atr.template as template
import atr.util as util
import atr.web as web


class ResolveVoteForm(forms.Typed):
    """Form for resolving a vote."""

    email_body = forms.textarea("Email body", optional=True, rows=24)
    vote_result = forms.radio(
        "Vote result",
        choices=[
            ("passed", "Passed"),
            ("failed", "Failed"),
        ],
    )
    submit = forms.submit("Resolve vote")


class ResolveVoteManualForm(forms.Typed):
    """Form for resolving a vote manually."""

    vote_result = forms.radio(
        "Vote result",
        choices=[
            ("passed", "Passed"),
            ("failed", "Failed"),
        ],
    )
    vote_thread_url = forms.string("Vote thread URL")
    vote_result_url = forms.string("Vote result URL")
    submit = forms.submit("Resolve vote")


@route.committer("/resolve/manual/<project_name>/<version_name>")
async def manual_selected(session: route.CommitterSession, project_name: str, version_name: str) -> str:
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


@route.committer("/resolve/manual/<project_name>/<version_name>", methods=["POST"])
async def manual_selected_post(
    session: route.CommitterSession, project_name: str, version_name: str
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
    if not (await resolve_form.validate_on_submit()):
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

    async with storage.write_as_project_committee_member(project_name) as wacm:
        success_message = await wacm.vote.resolve_manually(project_name, release, vote_result)
    if vote_result == "passed":
        destination = finish.selected
    else:
        destination = compose.selected

    return await session.redirect(
        destination, project_name=project_name, version_name=version_name, success=success_message
    )


@route.committer("/resolve/submit/<project_name>/<version_name>", methods=["POST"])
async def submit_selected(
    session: route.CommitterSession, project_name: str, version_name: str
) -> response.Response | str:
    """Resolve a vote."""
    await session.check_access(project_name)

    resolve_form = await ResolveVoteForm.create_form()
    if not (await resolve_form.validate_on_submit()):
        # TODO: Render the page again with errors
        return await session.redirect(
            vote.selected,
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
            destination = vote.selected
        else:
            destination = finish.selected
    else:
        destination = compose.selected

    return await session.redirect(
        destination, project_name=project_name, version_name=version_name, success=success_message
    )


@route.committer("/resolve/tabulated/<project_name>/<version_name>", methods=["POST"])
async def tabulated_selected_post(session: route.CommitterSession, project_name: str, version_name: str) -> str:
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

    hidden_form = await forms.Hidden.create_form()
    details = None
    committee = None
    thread_id = None
    archive_url = None
    fetch_error = None
    if await hidden_form.validate_on_submit():
        # TODO: Just pass the thread_id itself instead?
        # TODO: The hidden field is user controlled data, so we should HMAC it
        # Ideally there would be a concept of authenticated hidden fields
        # Perhaps all hidden fields should be authenticated
        # We should also still validate all HMACed fields
        archive_url = hidden_form.hidden_field.data or ""
        if archive_url:
            if not web.valid_url(archive_url, "lists.apache.org"):
                raise base.ASFQuartException("Invalid vote thread URL", errorcode=400)
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
    resolve_form = await ResolveVoteForm.create_form()
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
