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

import re
from typing import TYPE_CHECKING

import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.analysis as analysis
import atr.db as db
import atr.db.models as models
import atr.revision as revision
import atr.routes as routes
import atr.routes.draft as draft
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import Sequence


async def check(
    session: routes.CommitterSession,
    release: models.Release,
    task_mid: str | None = None,
    form: wtforms.Form | None = None,
) -> response.Response | str:
    base_path = util.release_directory(release)
    paths = await util.paths_recursive(base_path)
    path_templates = {}
    path_substitutions = {}
    path_artifacts = set()
    path_metadata = set()
    path_successes = {}
    path_warnings = {}
    path_errors = {}
    user_ssh_keys: Sequence[models.SSHKey] = []

    for path in paths:
        # Get template and substitutions
        elements = {
            "core": release.project.name,
            "version": release.version,
            "sub": None,
            "template": None,
            "substitutions": None,
        }
        template, substitutions = analysis.filename_parse(str(path), elements)
        path_templates[path] = template
        path_substitutions[path] = analysis.substitutions_format(substitutions) or "none"

        # Get artifacts and metadata
        search = re.search(analysis.extension_pattern(), str(path))
        if search:
            if search.group("artifact"):
                path_artifacts.add(path)
            elif search.group("metadata"):
                path_metadata.add(path)

        # Get successes, warnings, and errors
        async with db.session() as data:
            path_successes[path] = await data.check_result(
                release_name=release.name, primary_rel_path=str(path), status=models.CheckResultStatus.SUCCESS
            ).all()
            path_warnings[path] = await data.check_result(
                release_name=release.name, primary_rel_path=str(path), status=models.CheckResultStatus.WARNING
            ).all()
            path_errors[path] = await data.check_result(
                release_name=release.name, primary_rel_path=str(path), status=models.CheckResultStatus.FAILURE
            ).all()
            user_ssh_keys = await data.ssh_key(asf_uid=session.uid).all()

    revision_name_from_link, revision_editor, revision_time = await revision.latest_info(
        release.project.name, release.version
    )

    # Get the number of ongoing tasks for the current revision
    ongoing_tasks_count = 0
    if revision_name_from_link:
        ongoing_tasks_count = await db.tasks_ongoing(release.project.name, release.version, revision_name_from_link)

    delete_draft_form = await draft.DeleteForm.create_form()
    delete_file_form = await draft.DeleteFileForm.create_form()

    return await quart.render_template(
        "check-selected.html",
        project_name=release.project.name,
        version_name=release.version,
        release=release,
        paths=paths,
        artifacts=path_artifacts,
        metadata=path_metadata,
        successes=path_successes,
        warnings=path_warnings,
        errors=path_errors,
        templates=path_templates,
        substitutions=path_substitutions,
        revision_editor=revision_editor,
        revision_time=revision_time,
        revision_name_from_link=revision_name_from_link,
        ongoing_tasks_count=ongoing_tasks_count,
        delete_form=delete_draft_form,
        delete_file_form=delete_file_form,
        asf_id=session.uid,
        server_domain=session.host,
        user_ssh_keys=user_ssh_keys,
        format_datetime=util.format_datetime,
        models=models,
        task_mid=task_mid,
        form=form,
    )


@routes.committer("/compose/<project_name>/<version_name>")
async def selected(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Show the contents of the release candidate draft."""
    await session.check_access(project_name)

    release = await session.release(project_name, version_name, with_committee=True)
    return await check(session, release)
