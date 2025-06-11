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

import dataclasses

import aiofiles.os
import quart

import atr.config as config
import atr.db as db
import atr.db.models as models
import atr.util as util


@dataclasses.dataclass
class AnnounceReleaseOptions:
    asfuid: str
    fullname: str
    project_name: str
    version_name: str


@dataclasses.dataclass
class StartVoteOptions:
    asfuid: str
    fullname: str
    project_name: str
    version_name: str
    vote_duration: int


async def announce_release_body(body: str, options: AnnounceReleaseOptions) -> str:
    # NOTE: The present module is imported by routes
    # Therefore this must be done here to avoid a circular import
    import atr.routes.release as routes_release

    try:
        host = quart.request.host
    except RuntimeError:
        host = config.get().APP_HOST

    async with db.session() as data:
        release = await data.release(
            project_name=options.project_name,
            version=options.version_name,
            _project=True,
            _committee=True,
            phase=models.ReleasePhase.RELEASE_PREVIEW,
        ).demand(RuntimeError(f"Release {options.project_name} {options.version_name} not found"))
        committee_name = release.committee.display_name if release.committee else release.project.display_name

    routes_release_view = routes_release.view  # type: ignore[has-type]
    download_path = util.as_url(
        routes_release_view, project_name=options.project_name, version_name=options.version_name
    )
    # TODO: This download_url should probably be for the proxy download directory, not the ATR view
    download_url = f"https://{host}{download_path}"

    # Perform substitutions in the body
    body = body.replace("[COMMITTEE]", committee_name)
    body = body.replace("[DOWNLOAD_URL]", download_url)
    body = body.replace("[PROJECT]", options.project_name)
    body = body.replace("[VERSION]", options.version_name)
    body = body.replace("[YOUR_ASF_ID]", options.asfuid)
    body = body.replace("[YOUR_FULL_NAME]", options.fullname)

    return body


async def announce_release_default(project_name: str) -> str:
    async with db.session() as data:
        project = await data.project(name=project_name, _release_policy=True).demand(
            RuntimeError(f"Project {project_name} not found")
        )

    return project.policy_announce_release_template


async def start_vote_body(body: str, options: StartVoteOptions) -> str:
    async with db.session() as data:
        # Do not limit by phase, as it may be at RELEASE_CANDIDATE here if called by the task
        release = await data.release(
            project_name=options.project_name,
            version=options.version_name,
            _project=True,
            _committee=True,
        ).demand(RuntimeError(f"Release {options.project_name} {options.version_name} not found"))

    try:
        host = quart.request.host
    except RuntimeError:
        host = config.get().APP_HOST

    review_url = f"https://{host}/vote/{options.project_name}/{options.version_name}"
    committee_name = release.committee.display_name if release.committee else release.project.display_name
    project_short_display_name = release.project.short_display_name if release.project else options.project_name

    keys_file = None
    keys_file_path = util.get_finished_dir() / options.project_name / "KEYS"
    if await aiofiles.os.path.isfile(keys_file_path):
        keys_file = f"https://{host}/downloads/{options.project_name}/KEYS"

    checklist_content = ""
    async with db.session() as data:
        release_policy = await db.get_project_release_policy(data, options.project_name)
        if release_policy:
            checklist_content = release_policy.release_checklist or ""

    # Perform substitutions in the body
    # TODO: Handle the DURATION == 0 case
    body = body.replace("[COMMITTEE]", committee_name)
    body = body.replace("[DURATION]", str(options.vote_duration))
    body = body.replace("[KEYS_FILE]", keys_file or "[Sorry, the KEYS file is missing!]")
    body = body.replace("[PROJECT]", project_short_display_name)
    body = body.replace("[RELEASE_CHECKLIST]", checklist_content)
    body = body.replace("[REVIEW_URL]", review_url)
    body = body.replace("[VERSION]", options.version_name)
    body = body.replace("[YOUR_ASF_ID]", options.asfuid)
    body = body.replace("[YOUR_FULL_NAME]", options.fullname)

    return body


async def start_vote_default(project_name: str) -> str:
    async with db.session() as data:
        project = await data.project(name=project_name, _release_policy=True).demand(
            RuntimeError(f"Project {project_name} not found")
        )

    return project.policy_start_vote_template
