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

from typing import TYPE_CHECKING, Final

import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.interaction as interaction
import atr.forms as forms
import atr.models.results as results
import atr.models.sql as sql
import atr.shared.announce as announce
import atr.shared.distribution as distribution
import atr.shared.draft as draft
import atr.shared.finish as finish
import atr.shared.ignores as ignores
import atr.shared.keys as keys
import atr.shared.projects as projects
import atr.shared.resolve as resolve
import atr.shared.start as start
import atr.shared.tokens as tokens
import atr.shared.upload as upload
import atr.shared.vote as vote
import atr.storage as storage
import atr.template as template
import atr.util as util
import atr.web as web

if TYPE_CHECKING:
    from collections.abc import Sequence


# |         1 | RSA (Encrypt or Sign) [HAC]                        |
# |         2 | RSA Encrypt-Only [HAC]                             |
# |         3 | RSA Sign-Only [HAC]                                |
# |        16 | Elgamal (Encrypt-Only) [ELGAMAL] [HAC]             |
# |        17 | DSA (Digital Signature Algorithm) [FIPS186] [HAC]  |
# |        18 | ECDH public key algorithm                          |
# |        19 | ECDSA public key algorithm [FIPS186]               |
# |        20 | Reserved (formerly Elgamal Encrypt or Sign)        |
# |        21 | Reserved for Diffie-Hellman                        |
# |           | (X9.42, as defined for IETF-S/MIME)                |
# |        22 | EdDSA [I-D.irtf-cfrg-eddsa]                        |
# - https://lists.gnupg.org/pipermail/gnupg-devel/2017-April/032762.html

algorithms: Final[dict[int, str]] = {
    1: "RSA",
    2: "RSA",
    3: "RSA",
    16: "Elgamal",
    17: "DSA",
    18: "ECDH",
    19: "ECDSA",
    21: "Diffie-Hellman",
    22: "EdDSA",
}


async def check(
    session: web.Committer | None,
    release: sql.Release,
    task_mid: str | None = None,
    form: wtforms.Form | None = None,
    hidden_form: wtforms.Form | None = None,
    archive_url: str | None = None,
    vote_task: sql.Task | None = None,
    can_vote: bool = False,
    can_resolve: bool = False,
) -> response.Response | str:
    base_path = util.release_directory(release)

    # TODO: This takes 180ms for providers
    # We could cache it
    paths = [path async for path in util.paths_recursive(base_path)]
    paths.sort()

    async with storage.read(session) as read:
        ragp = read.as_general_public()
        info = await ragp.releases.path_info(release, paths)

    user_ssh_keys: Sequence[sql.SSHKey] = []
    asf_id: str | None = None
    server_domain: str | None = None
    server_host: str | None = None

    if session is not None:
        asf_id = session.uid
        server_domain = session.app_host.split(":", 1)[0]
        server_host = session.app_host
        async with db.session() as data:
            user_ssh_keys = await data.ssh_key(asf_uid=session.uid).all()

    # Get the number of ongoing tasks for the current revision
    ongoing_tasks_count = 0
    match await interaction.latest_info(release.project.name, release.version):
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
    empty_form = await forms.Empty.create_form()
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
        asf_id=asf_id,
        server_domain=server_domain,
        server_host=server_host,
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
        can_vote=can_vote,
        can_resolve=can_resolve,
    )


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


__all__ = [
    "algorithms",
    "announce",
    "check",
    "distribution",
    "draft",
    "finish",
    "ignores",
    "keys",
    "projects",
    "resolve",
    "start",
    "tokens",
    "upload",
    "vote",
]
