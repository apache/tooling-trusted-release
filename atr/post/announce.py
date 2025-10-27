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
import werkzeug.wrappers.response as response

# TODO: Improve upon the routes_release pattern
import atr.blueprints.post as post
import atr.get as get
import atr.models.sql as sql
import atr.routes.release as routes_release
import atr.shared as shared
import atr.storage as storage
import atr.template as template
import atr.util as util
import atr.web as web


class AnnounceError(Exception):
    """Exception for announce errors."""


@post.committer("/announce/<project_name>/<version_name>")
async def selected(session: web.Committer, project_name: str, version_name: str) -> str | response.Response:
    """Handle the announcement form submission and promote the preview to release."""
    await session.check_access(project_name)

    permitted_recipients = util.permitted_announce_recipients(session.uid)
    announce_form = await shared.announce.create_form(
        permitted_recipients,
        data=await quart.request.form,
    )

    if not (await announce_form.validate_on_submit()):
        error_message = "Invalid submission"
        if announce_form.errors:
            error_details = "; ".join([f"{field}: {', '.join(errs)}" for field, errs in announce_form.errors.items()])
            error_message = f"{error_message}: {error_details}"

        # Render the page again, with errors
        release: sql.Release = await session.release(
            project_name, version_name, with_committee=True, phase=sql.ReleasePhase.RELEASE_PREVIEW
        )
        await quart.flash(error_message, "error")
        return await template.render("announce-selected.html", release=release, announce_form=announce_form)

    recipient = str(announce_form.mailing_list.data)
    if recipient not in permitted_recipients:
        raise AnnounceError(f"You are not permitted to send announcements to {recipient}")

    subject = str(announce_form.subject.data)
    body = str(announce_form.body.data)
    preview_revision_number = str(announce_form.preview_revision.data)
    download_path_suffix = _download_path_suffix_validated(announce_form)

    try:
        async with storage.write_as_project_committee_member(project_name, session) as wacm:
            await wacm.announce.release(
                project_name,
                version_name,
                preview_revision_number,
                recipient,
                subject,
                body,
                download_path_suffix,
                session.uid,
                session.fullname,
            )
    except storage.AccessError as e:
        return await session.redirect(
            get.announce.selected, error=str(e), project_name=project_name, version_name=version_name
        )

    routes_release_finished = routes_release.finished  # type: ignore[has-type]
    return await session.redirect(
        routes_release_finished,
        success="Preview successfully announced",
        project_name=project_name,
    )


def _download_path_suffix_validated(announce_form: shared.announce.Form) -> str:
    download_path_suffix = str(announce_form.download_path_suffix.data)
    if (".." in download_path_suffix) or ("//" in download_path_suffix):
        raise ValueError("Download path suffix must not contain .. or //")
    if download_path_suffix.startswith("./"):
        download_path_suffix = download_path_suffix[1:]
    elif download_path_suffix == ".":
        download_path_suffix = "/"
    if not download_path_suffix.startswith("/"):
        download_path_suffix = "/" + download_path_suffix
    if not download_path_suffix.endswith("/"):
        download_path_suffix = download_path_suffix + "/"
    if "/." in download_path_suffix:
        raise ValueError("Download path suffix must not contain /.")
    return download_path_suffix
