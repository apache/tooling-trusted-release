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

import atr.db as db
import atr.db.interaction as interaction
import atr.models.sql as sql
import atr.user as user
import atr.util as util
import atr.web as web


async def validated_release(
    session: web.Committer,
    project_name: str,
    version_name: str,
    revision: str,
    data: db.Session,
) -> tuple[sql.Release, sql.Committee] | str:
    """Validate release for manual vote and return (release, committee) or error message."""
    release = await session.release(
        project_name,
        version_name,
        data=data,
        with_project=True,
        with_committee=True,
        with_project_release_policy=True,
    )

    selected_revision_number = release.latest_revision_number
    if selected_revision_number is None:
        return "No revision found for this release"

    if selected_revision_number != revision:
        return "This revision does not match the revision you are voting on"

    committee = release.committee
    if committee is None:
        return "The committee for this release was not found"

    if not release.project.policy_manual_vote:
        return "This release does not have manual vote mode enabled"

    if release.project.policy_strict_checking:
        if await interaction.has_failing_checks(release, revision, caller_data=data):
            return "This release candidate draft has errors. Please fix the errors before starting a vote."

    if not (user.is_committee_member(committee, session.uid) or user.is_admin(session.uid)):
        return "You must be on the PMC of this project to start a vote"

    has_files = await util.has_files(release)
    if not has_files:
        return "This release candidate draft has no files yet. Please add some files before starting a vote."

    return release, committee
