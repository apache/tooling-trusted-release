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

"""Apache specific data-sources."""

from __future__ import annotations

import datetime
from typing import Annotated, Any, Final

import aiohttp

import atr.models.helpers as helpers
import atr.models.schema as schema

_WHIMSY_COMMITTEE_INFO_URL: Final[str] = "https://whimsy.apache.org/public/committee-info.json"
_WHIMSY_COMMITTEE_RETIRED_URL: Final[str] = "https://whimsy.apache.org/public/committee-retired.json"
_WHIMSY_PROJECTS_URL: Final[str] = "https://whimsy.apache.org/public/public_ldap_projects.json"
_PROJECTS_PROJECTS_URL: Final[str] = "https://projects.apache.org/json/foundation/projects.json"
_PROJECTS_PODLINGS_URL: Final[str] = "https://projects.apache.org/json/foundation/podlings.json"
_PROJECTS_GROUPS_URL: Final[str] = "https://projects.apache.org/json/foundation/groups.json"


class RosterCountDetails(schema.Strict):
    members: int
    owners: int


class LDAPProjectsData(schema.Strict):
    last_timestamp: str = schema.alias("lastTimestamp")
    project_count: int
    roster_counts: dict[str, RosterCountDetails]
    projects: Annotated[list[LDAPProject], helpers.DictToList(key="name")]

    @property
    def last_time(self) -> datetime.datetime:
        return datetime.datetime.strptime(self.last_timestamp, "%Y%m%d%H%M%S%z")


class LDAPProject(schema.Strict):
    name: str
    create_timestamp: str = schema.alias("createTimestamp")
    modify_timestamp: str = schema.alias("modifyTimestamp")
    member_count: int
    owner_count: int
    members: list[str]
    owners: list[str]
    pmc: bool = False
    podling: str | None = None


class User(schema.Strict):
    id: str
    name: str
    date: str | None = None


class Committee(schema.Strict):
    name: str
    display_name: str
    site: str | None
    description: str | None
    mail_list: str
    established: str | None
    report: list[str]
    chair: Annotated[list[User], helpers.DictToList(key="id")]
    roster_count: int
    roster: Annotated[list[User], helpers.DictToList(key="id")]
    pmc: bool


class CommitteeData(schema.Strict):
    last_updated: str
    committee_count: int
    pmc_count: int
    roster_counts: dict[str, int] = schema.factory(dict)
    officers: dict[str, Any] = schema.factory(dict)
    board: dict[str, Any] = schema.factory(dict)
    committees: Annotated[list[Committee], helpers.DictToList(key="name")]


class RetiredCommittee(schema.Strict):
    name: str
    display_name: str
    retired: str
    description: str | None


class RetiredCommitteeData(schema.Strict):
    last_updated: str
    retired_count: int
    retired: Annotated[list[RetiredCommittee], helpers.DictToList(key="name")]


class PodlingStatus(schema.Strict):
    description: str
    homepage: str
    name: str = schema.alias("name")
    pmc: str
    podling: bool
    started: str
    champion: str | None = None
    retiring: bool | None = None
    resolution: str | None = None


class PodlingsData(helpers.DictRoot[PodlingStatus]):
    pass


class GroupsData(helpers.DictRoot[list[str]]):
    pass


class MaintainerInfo(schema.Strict):
    mbox: str | None = None
    name: str | None = None
    homepage: str | None = None
    mbox_sha1sum: str | None = None
    nick: str | None = None
    same_as: str | None = schema.alias_opt("sameAs")


class PersonInfo(schema.Strict):
    name: str | None = None
    homepage: str | None = None
    mbox: str | None = None


class ChairInfo(schema.Strict):
    person: PersonInfo | None = schema.alias_opt("Person")


class HelperInfo(schema.Strict):
    name: str | None = None
    homepage: str | None = None


class OnlineAccountInfo(schema.Strict):
    account_service_homepage: str | None = schema.alias_opt("accountServiceHomepage")
    account_name: str | None = schema.alias_opt("accountName")
    account_profile_page: str | None = schema.alias_opt("accountProfilePage")


class AccountInfo(schema.Strict):
    online_account: OnlineAccountInfo | None = schema.alias_opt("OnlineAccount")


class ImplementsInfo(schema.Strict):
    body: str | None = None
    id: str | None = None
    resource: str | None = None
    title: str | None = None
    url: str | None = None


class Release(schema.Strict):
    created: str | None = None
    name: str
    revision: str | None = None
    file_release: str | None = schema.alias_opt("file-release")
    description: str | None = None
    branch: str | None = None


class ProjectStatus(schema.Strict):
    category: str | None = None
    created: str | None = None
    description: str | None = None
    programming_language: str | None = schema.alias_opt("programming-language")
    doap: str | None = None
    homepage: str
    name: str
    pmc: str
    shortdesc: str | None = None
    repository: list[str | dict] = schema.factory(list)
    release: list[Release] = schema.factory(list)
    bug_database: str | None = schema.alias_opt("bug-database")
    download_page: str | None = schema.alias_opt("download-page")
    license: str | None = None
    mailing_list: str | None = schema.alias_opt("mailing-list")
    maintainer: list[MaintainerInfo] = schema.factory(list)
    implements: list[ImplementsInfo] = schema.factory(list)
    same_as: str | None = schema.alias_opt("sameAs")
    developer: list[MaintainerInfo] = schema.factory(list)
    modified: str | None = None
    chair: ChairInfo | None = None
    charter: str | None = None
    vendor: str | None = None
    helper: list[HelperInfo] = schema.factory(list)
    member: list[MaintainerInfo] = schema.factory(list)
    shortname: str | None = None
    wiki: str | None = None
    account: AccountInfo | None = None
    platform: str | None = None


class ProjectsData(helpers.DictRoot[ProjectStatus]):
    pass


async def get_active_committee_data() -> CommitteeData:
    """Returns the list of currently active committees."""

    async with aiohttp.ClientSession() as session:
        async with session.get(_WHIMSY_COMMITTEE_INFO_URL) as response:
            response.raise_for_status()
            data = await response.json()

    return CommitteeData.model_validate(data)


async def get_current_podlings_data() -> PodlingsData:
    """Returns the list of current podlings."""

    async with aiohttp.ClientSession() as session:
        async with session.get(_PROJECTS_PODLINGS_URL) as response:
            response.raise_for_status()
            data = await response.json()
    return PodlingsData.model_validate(data)


async def get_groups_data() -> GroupsData:
    """Returns LDAP Groups with their members."""

    async with aiohttp.ClientSession() as session:
        async with session.get(_PROJECTS_GROUPS_URL) as response:
            response.raise_for_status()
            data = await response.json()
    return GroupsData.model_validate(data)


async def get_ldap_projects_data() -> LDAPProjectsData:
    async with aiohttp.ClientSession() as session:
        async with session.get(_WHIMSY_PROJECTS_URL) as response:
            response.raise_for_status()
            data = await response.json()

    return LDAPProjectsData.model_validate(data)


async def get_projects_data() -> ProjectsData:
    """Returns the list of projects."""

    async with aiohttp.ClientSession() as session:
        async with session.get(_PROJECTS_PROJECTS_URL) as response:
            response.raise_for_status()
            data = await response.json()
    return ProjectsData.model_validate(data)


async def get_retired_committee_data() -> RetiredCommitteeData:
    """Returns the list of retired committees."""

    async with aiohttp.ClientSession() as session:
        async with session.get(_WHIMSY_COMMITTEE_RETIRED_URL) as response:
            response.raise_for_status()
            data = await response.json()

    return RetiredCommitteeData.model_validate(data)
