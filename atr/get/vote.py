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

import atr.blueprints.get as get
import atr.db as db
import atr.db.interaction as interaction
import atr.forms as forms
import atr.log as log
import atr.mapping as mapping
import atr.models.results as results
import atr.models.sql as sql
import atr.shared as shared
import atr.storage as storage
import atr.user as user
import atr.util as util
import atr.web as web


@get.public("/vote/<project_name>/<version_name>")
async def selected(session: web.Committer | None, project_name: str, version_name: str) -> web.WerkzeugResponse | str:
    """Show the contents of the release candidate draft."""
    async with db.session() as data:
        release = await data.release(
            project_name=project_name,
            version=version_name,
            _committee=True,
            _project_release_policy=True,
        ).demand(base.ASFQuartException("Release does not exist", errorcode=404))

    if release.phase != sql.ReleasePhase.RELEASE_CANDIDATE:
        if session is None:
            raise base.ASFQuartException("Release is not a candidate", errorcode=404)
        return await mapping.release_as_redirect(session, release)

    if release.committee is None:
        raise ValueError("Release has no committee")

    is_authenticated = session is not None
    is_committee_member = is_authenticated and (
        user.is_committee_member(release.committee, session.uid) or user.is_admin(session.uid)
    )
    can_vote = is_committee_member
    can_resolve = is_committee_member

    latest_vote_task = await interaction.release_latest_vote_task(release)
    archive_url = None
    task_mid = None

    if latest_vote_task is not None:
        if util.is_dev_environment():
            log.warning("Setting vote task to completed in dev environment")
            latest_vote_task.status = sql.TaskStatus.COMPLETED
            latest_vote_task.result = results.VoteInitiate(
                kind="vote_initiate",
                message="Vote announcement email sent successfully",
                email_to="example@example.org.INVALID",
                vote_end="2025-07-01 12:00:00",
                subject="Test vote",
                mid=interaction.TEST_MID,
                mail_send_warnings=[],
            )

        # Move task_mid_get here?
        task_mid = interaction.task_mid_get(latest_vote_task)
        async with storage.write(session) as write:
            wagp = write.as_general_public()
            archive_url = await wagp.cache.get_message_archive_url(task_mid)

    resolve_form = None
    if can_resolve:
        # Special form for the [ Resolve vote ] button, to make it POST
        resolve_form = await forms.Submit.create_form()
        resolve_form.submit.label.text = "Resolve vote"

    form = None
    if can_vote:
        form = await shared.vote.CastVoteForm.create_form()
        async with storage.write() as write:
            try:
                if release.committee.is_podling:
                    _wacm = write.as_committee_member("incubator")
                else:
                    _wacm = write.as_committee_member(release.committee.name)
                potency = "Binding"
            except storage.AccessError:
                potency = "Non-binding"
        forms.choices(
            form.vote_value,
            choices=[
                ("+1", f"+1 ({potency})"),
                ("0", "0"),
                ("-1", f"-1 ({potency})"),
            ],
        )

    return await shared.check(
        session,
        release,
        task_mid=task_mid,
        form=form,
        resolve_form=resolve_form,
        archive_url=archive_url,
        vote_task=latest_vote_task,
        can_vote=can_vote,
        can_resolve=can_resolve,
    )
