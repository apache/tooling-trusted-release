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

"""user.py"""

import functools

import atr.config as config
import atr.db as db
import atr.db.models as models


async def candidate_drafts(uid: str, user_projects: list[models.Project] | None = None) -> list[models.Release]:
    if user_projects is None:
        user_projects = await projects(uid)
    user_candidate_drafts: list[models.Release] = []
    for p in user_projects:
        releases = await p.candidate_drafts
        user_candidate_drafts.extend(releases)
    return user_candidate_drafts


@functools.cache
def get_admin_users() -> set[str]:
    return set(config.get().ADMIN_USERS)


def is_admin(user_id: str | None) -> bool:
    """Check whether a user is an admin."""
    if user_id is None:
        return False
    return user_id in get_admin_users()


def is_committee_member(committee: models.Committee | None, uid: str) -> bool:
    if committee is None:
        return False
    return any((member_uid == uid) for member_uid in committee.committee_members)


def is_committer(committee: models.Committee | None, uid: str) -> bool:
    if committee is None:
        return False
    return any((committer_uid == uid) for committer_uid in committee.committers)


async def projects(uid: str, committee_only: bool = False, super_project: bool = False) -> list[models.Project]:
    user_projects: list[models.Project] = []
    async with db.session() as data:
        # Must have releases, because this is used in candidate_drafts
        projects = await data.project(
            status=models.ProjectStatus.ACTIVE, _committee=True, _releases=True, _super_project=super_project
        ).all()
        for p in projects:
            if p.committee is None:
                continue
            if committee_only:
                if uid in p.committee.committee_members:
                    user_projects.append(p)
            else:
                if (uid in p.committee.committee_members) or (uid in p.committee.committers):
                    user_projects.append(p)
    return user_projects
