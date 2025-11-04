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


import aioshutil
import asfquart.base as base
import quart

import atr.blueprints.post as post
import atr.db as db
import atr.get as get
import atr.models.sql as sql
import atr.storage as storage
import atr.util as util
import atr.web as web


@post.committer("/revisions/<project_name>/<version_name>")
async def selected_post(session: web.Committer, project_name: str, version_name: str) -> web.WerkzeugResponse:
    """Set a specific revision as the latest for a candidate draft or release preview."""
    await session.check_access(project_name)

    # TODO: This is not truly empty, so make a form object for this
    await util.validate_empty_form()
    form_data = await quart.request.form
    selected_revision_number = form_data.get("revision_number")
    if not selected_revision_number:
        raise base.ASFQuartException("Missing revision number", errorcode=400)

    async with db.session() as data:
        release = await session.release(project_name, version_name, phase=None, data=data)
        selected_revision_dir = util.release_directory_base(release) / selected_revision_number
        if release.phase not in {sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT, sql.ReleasePhase.RELEASE_PREVIEW}:
            raise base.ASFQuartException("Cannot set revision for non-draft or preview release", errorcode=400)

        selected_revision = await data.revision(release_name=release.name, number=selected_revision_number).demand(
            base.ASFQuartException(f"Revision {selected_revision_number} not found", errorcode=404)
        )
        if (release.phase == sql.ReleasePhase.RELEASE_PREVIEW) and (
            selected_revision.phase != sql.ReleasePhase.RELEASE_PREVIEW
        ):
            raise base.ASFQuartException(
                f"Revision {selected_revision_number} is not a preview revision", errorcode=400
            )

    description = f"Copy of revision {selected_revision_number} through web interface"
    async with storage.write(session) as write:
        wacp = await write.as_project_committee_participant(project_name)
        async with wacp.revision.create_and_manage(
            project_name, version_name, session.uid, description=description
        ) as creating:
            # TODO: Stop create_and_manage from hard linking the parent first
            await aioshutil.rmtree(creating.interim_path)  # type: ignore[call-arg]
            await util.create_hard_link_clone(selected_revision_dir, creating.interim_path)

        if creating.new is None:
            raise base.ASFQuartException("Internal error: New revision not found", errorcode=500)
        return await session.redirect(
            get.revisions.selected,
            success=f"Copied revision {selected_revision_number} to new latest revision, {creating.new.number}",
            project_name=project_name,
            version_name=version_name,
        )
