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

from __future__ import annotations

# TODO: Improve upon the routes_release pattern
import atr.blueprints.post as post
import atr.get as get
import atr.models.sql as sql
import atr.shared as shared
import atr.storage as storage
import atr.util as util
import atr.web as web


@post.committer("/announce/<project_name>/<version_name>")
@post.form(shared.announce.AnnounceForm)
async def selected(
    session: web.Committer, announce_form: shared.announce.AnnounceForm, project_name: str, version_name: str
) -> web.WerkzeugResponse:
    """Handle the announcement form submission and promote the preview to release."""
    await session.check_access(project_name)

    permitted_recipients = util.permitted_announce_recipients(session.uid)

    # Validate that the recipient is permitted
    if announce_form.mailing_list not in permitted_recipients:
        return await session.form_error(
            "mailing_list",
            f"You are not permitted to send announcements to {announce_form.mailing_list}",
        )

    # Get the release to find the revision number
    release = await session.release(
        project_name, version_name, with_committee=True, phase=sql.ReleasePhase.RELEASE_PREVIEW
    )
    preview_revision_number = release.unwrap_revision_number

    # Validate that the revision number matches
    if announce_form.revision_number != preview_revision_number:
        return await session.redirect(
            get.announce.selected,
            error=f"The release has been updated since you loaded the form. "
            f"Please review the current revision ({preview_revision_number}) and submit the form again.",
            project_name=project_name,
            version_name=version_name,
        )

    try:
        async with storage.write_as_project_committee_member(project_name, session) as wacm:
            await wacm.announce.release(
                project_name,
                version_name,
                preview_revision_number,
                announce_form.mailing_list,
                announce_form.subject,
                announce_form.body,
                announce_form.download_path_suffix,
                session.uid,
                session.fullname,
            )
    except storage.AccessError as e:
        return await session.redirect(
            get.announce.selected, error=str(e), project_name=project_name, version_name=version_name
        )

    routes_release_finished = get.release.finished  # type: ignore[has-type]
    return await session.redirect(
        routes_release_finished,
        success="Preview successfully announced",
        project_name=project_name,
    )
