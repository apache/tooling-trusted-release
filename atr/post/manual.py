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

import atr.blueprints.post as post
import atr.db as db
import atr.db.interaction as interaction
import atr.get as get
import atr.models.sql as sql
import atr.shared as shared
import atr.storage as storage
import atr.util as util
import atr.web as web


@post.committer("/manual/resolve/<project_name>/<version_name>")
@post.form(shared.manual.ResolveVoteForm)
async def resolve_selected(
    session: web.Committer,
    resolve_vote_form: shared.manual.ResolveVoteForm,
    project_name: str,
    version_name: str,
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

    try:
        await _committees_check(resolve_vote_form.vote_thread_url, resolve_vote_form.vote_result_url)
    except RuntimeError as e:
        return await session.redirect(
            get.manual.resolve_selected,
            project_name=project_name,
            version_name=version_name,
            error=str(e),
        )

    match resolve_vote_form.vote_result:
        case "Passed":
            vote_result = "passed"
            destination = get.finish.selected
        case "Failed":
            vote_result = "failed"
            destination = get.compose.selected

    async with storage.write_as_project_committee_member(project_name) as wacm:
        success_message = await wacm.vote.resolve_manually(project_name, release, vote_result)

    return await session.redirect(
        destination, project_name=project_name, version_name=version_name, success=success_message
    )


@post.committer("/manual/start/<project_name>/<version_name>/<revision>")
@post.empty()
async def start_selected_revision(
    session: web.Committer, project_name: str, version_name: str, revision: str
) -> web.WerkzeugResponse | str:
    await session.check_access(project_name)

    async with db.session() as data:
        match await interaction.release_ready_for_vote(
            session, project_name, version_name, revision, data, manual_vote=True
        ):
            case str() as error:
                return await session.redirect(
                    get.vote.selected,
                    error=error,
                    project_name=project_name,
                    version_name=version_name,
                )
            case (release, _committee):
                pass

        async with storage.write(session) as write:
            wacp = await write.as_project_committee_participant(release.project_name)
            error = await wacp.release.promote_to_candidate(release.name, revision, vote_manual=True)

        if error:
            return await session.redirect(
                get.vote.selected,
                error=error,
                project_name=project_name,
                version_name=version_name,
            )

        return await session.redirect(
            get.vote.selected,
            success="The manual vote process has been started.",
            project_name=project_name,
            version_name=version_name,
        )


async def _committee_label(thread_id: str) -> str | None:
    async for _mid, msg in util.thread_messages(thread_id):
        if "list_raw" in msg:
            list_raw = msg["list_raw"]
            return list_raw.split(".apache.org", 1)[0].split(".", 1)[-1]
    return None


async def _committees_check(vote_thread_url: str, vote_result_url: str) -> None:
    vote_thread_id = vote_thread_url.removeprefix("https://lists.apache.org/thread/")
    result_thread_id = vote_result_url.removeprefix("https://lists.apache.org/thread/")

    try:
        vote_committee_label = await _committee_label(vote_thread_id)
    except util.FetchError as e:
        raise RuntimeError(f"Failed to fetch vote thread metadata from URL {e.url}: {e!s}")
    try:
        result_committee_label = await _committee_label(result_thread_id)
    except util.FetchError as e:
        raise RuntimeError(f"Failed to fetch vote thread metadata from URL {e.url}: {e!s}")

    if vote_committee_label != result_committee_label:
        raise RuntimeError("Vote committee and result committee do not match")

    if vote_committee_label is None:
        raise RuntimeError("Vote committee not found")
    if result_committee_label is None:
        raise RuntimeError("Result committee not found")
