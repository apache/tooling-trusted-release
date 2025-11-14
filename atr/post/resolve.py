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
import atr.form
import atr.get as get
import atr.models.sql as sql
import atr.shared as shared
import atr.storage as storage
import atr.tabulate as tabulate
import atr.template as template
import atr.util as util
import atr.web as web


@post.committer("/resolve/<project_name>/<version_name>")
@post.form(shared.resolve.ResolveForm)
async def selected(
    session: web.Committer, resolve_form: shared.resolve.ResolveForm, project_name: str, version_name: str
) -> web.WerkzeugResponse | str:
    await session.check_access(project_name)

    match resolve_form:
        case shared.resolve.SubmitForm() as submit_form:
            return await _submit(session, submit_form, project_name, version_name)

        case shared.resolve.TabulateForm():
            return await _tabulate(session, project_name, version_name)


async def _submit(
    session: web.Committer, submit_form: shared.resolve.SubmitForm, project_name: str, version_name: str
) -> web.WerkzeugResponse:
    email_body = submit_form.email_body
    vote_result = submit_form.vote_result

    async with storage.write_as_project_committee_member(project_name) as wacm:
        _release, voting_round, success_message, error_message = await wacm.vote.resolve(
            project_name,
            version_name,
            "passed" if vote_result == "Passed" else "failed",
            session.fullname,
            email_body,
        )
    if error_message is not None:
        await quart.flash(error_message, "error")

    match (vote_result, voting_round):
        case "Passed", 1:
            destination = get.vote.selected
        case "Passed", _:
            destination = get.finish.selected
        case "Failed", _:
            destination = get.compose.selected

    return await session.redirect(
        destination, project_name=project_name, version_name=version_name, success=success_message
    )


async def _tabulate(session: web.Committer, project_name: str, version_name: str) -> str:
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

    details = None
    committee = None
    thread_id = None
    archive_url = None
    fetch_error = None

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

    defaults = {}
    if (committee is not None) and (details is not None) and (thread_id is not None):
        defaults["email_body"] = tabulate.vote_resolution(
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
        defaults["vote_result"] = "passed" if details.passed else "failed"

    resolve_form = atr.form.render(
        model_cls=shared.resolve.SubmitForm,
        action=util.as_url(selected, project_name=release.project.name, version_name=release.version),
        submit_label="Resolve vote",
        textarea_rows=24,
        defaults=defaults,
    )

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
