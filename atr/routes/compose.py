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

from typing import TYPE_CHECKING

import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.interaction as interaction
import atr.models.results as results
import atr.models.sql as sql
import atr.revision as revision
import atr.routes as routes
import atr.routes.draft as draft
import atr.storage as storage
import atr.template as template
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import Sequence


async def check(
    session: routes.CommitterSession,
    release: sql.Release,
    task_mid: str | None = None,
    form: wtforms.Form | None = None,
    hidden_form: wtforms.Form | None = None,
    archive_url: str | None = None,
    vote_task: sql.Task | None = None,
) -> response.Response | str:
    base_path = util.release_directory(release)

    # TODO: This takes 180ms for providers
    # We could cache it
    paths = [path async for path in util.paths_recursive(base_path)]
    paths.sort()

    async with storage.read() as read:
        ragp = read.as_general_public()
        info = await ragp.releases.path_info(release, paths)

    user_ssh_keys: Sequence[sql.SSHKey] = []
    async with db.session() as data:
        user_ssh_keys = await data.ssh_key(asf_uid=session.uid).all()

    # Get the number of ongoing tasks for the current revision
    ongoing_tasks_count = 0
    match await revision.latest_info(release.project.name, release.version):
        case (revision_number, revision_editor, revision_timestamp):
            ongoing_tasks_count = await interaction.tasks_ongoing(
                release.project.name,
                release.version,
                revision_number,  # type: ignore[arg-type]
            )
        case None:
            revision_number = None  # type: ignore[assignment]
            revision_editor = None  # type: ignore[assignment]
            revision_timestamp = None  # type: ignore[assignment]

    delete_draft_form = await draft.DeleteForm.create_form(
        data={"release_name": release.name, "project_name": release.project.name, "version_name": release.version}
    )
    delete_file_form = await draft.DeleteFileForm.create_form()
    empty_form = await util.EmptyForm.create_form()
    vote_task_warnings = _warnings_from_vote_result(vote_task)
    has_files = await util.has_files(release)

    has_any_errors = any(info.errors.get(path, []) for path in paths) if info else False
    strict_checking = release.project.policy_strict_checking
    strict_checking_errors = strict_checking and has_any_errors

    return await template.render(
        "check-selected.html",
        project_name=release.project.name,
        version_name=release.version,
        release=release,
        paths=paths,
        info=info,
        revision_editor=revision_editor,
        revision_time=revision_timestamp,
        revision_number=revision_number,
        ongoing_tasks_count=ongoing_tasks_count,
        delete_form=delete_draft_form,
        delete_file_form=delete_file_form,
        asf_id=session.uid,
        server_domain=session.app_host.split(":", 1)[0],
        server_host=session.app_host,
        user_ssh_keys=user_ssh_keys,
        format_datetime=util.format_datetime,
        models=sql,
        task_mid=task_mid,
        form=form,
        vote_task=vote_task,
        archive_url=archive_url,
        vote_task_warnings=vote_task_warnings,
        empty_form=empty_form,
        hidden_form=hidden_form,
        has_files=has_files,
        strict_checking_errors=strict_checking_errors,
    )


@routes.committer("/compose/<project_name>/<version_name>")
async def selected(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Show the contents of the release candidate draft."""
    await session.check_access(project_name)

    release = await session.release(project_name, version_name, with_committee=True, with_project_release_policy=True)
    return await check(session, release)


def _warnings_from_vote_result(vote_task: sql.Task | None) -> list[str]:
    # TODO: Replace this with a schema.Strict model
    # But we'd still need to do some of this parsing and validation
    # We should probably rethink how to send data through tasks

    if not vote_task or (not vote_task.result):
        return ["No vote task result found."]

    vote_task_result = vote_task.result
    if not isinstance(vote_task_result, results.VoteInitiate):
        return ["Vote task result is not a results.VoteInitiate instance."]

    return vote_task_result.mail_send_warnings
