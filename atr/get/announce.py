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

import werkzeug.wrappers.response as response

# TODO: Improve upon the routes_release pattern
import atr.blueprints.get as get
import atr.config as config
import atr.construct as construct
import atr.models.sql as sql
import atr.shared as shared
import atr.template as template
import atr.util as util
import atr.web as web


@get.committer("/announce/<project_name>/<version_name>")
async def selected(session: web.Committer, project_name: str, version_name: str) -> str | response.Response:
    """Allow the user to announce a release preview."""
    await session.check_access(project_name)

    release = await session.release(
        project_name, version_name, with_committee=True, phase=sql.ReleasePhase.RELEASE_PREVIEW
    )
    announce_form = await shared.announce.create_form(util.permitted_announce_recipients(session.uid))
    # Hidden fields
    announce_form.preview_name.data = release.name
    # There must be a revision to announce
    announce_form.preview_revision.data = release.unwrap_revision_number

    # Variables used in defaults for subject and body
    project_display_name = release.project.display_name or release.project.name

    # The subject cannot be changed by the user
    announce_form.subject.data = f"[ANNOUNCE] {project_display_name} {version_name} released"
    # The body can be changed, either from VoteTemplate or from the form
    announce_form.body.data = await construct.announce_release_default(project_name)
    # The download path suffix can be changed
    # The defaults depend on whether the project is top level or not
    if (committee := release.project.committee) is None:
        raise ValueError("Release has no committee")
    top_level_project = release.project.name == util.unwrap(committee.name)
    # These defaults are as per #136, but we allow the user to change the result
    announce_form.download_path_suffix.data = (
        "/" if top_level_project else f"/{release.project.name}-{release.version}/"
    )
    # This must NOT end with a "/"
    description_download_prefix = f"https://{config.get().APP_HOST}/downloads"
    if committee.is_podling:
        description_download_prefix += "/incubator"
    description_download_prefix += f"/{committee.name}"
    announce_form.download_path_suffix.description = f"The URL will be {description_download_prefix} plus this suffix"

    return await template.render(
        "announce-selected.html",
        release=release,
        announce_form=announce_form,
        user_tests_address=util.USER_TESTS_ADDRESS,
    )
