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
from typing import Annotated, Final

import httpx
import pydantic

import atr.util as util

_WHIMSY_COMMITTEE_INFO_URL: Final[str] = "https://whimsy.apache.org/public/committee-info.json"
_WHIMSY_COMMITTEE_RETIRED_URL: Final[str] = "https://whimsy.apache.org/public/committee-retired.json"
_WHIMSY_PROJECTS_URL: Final[str] = "https://whimsy.apache.org/public/public_ldap_projects.json"
_PROJECTS_PROJECTS_URL: Final[str] = "https://projects.apache.org/json/foundation/projects.json"
_PROJECTS_PODLINGS_URL: Final[str] = "https://projects.apache.org/json/foundation/podlings.json"
_PROJECTS_GROUPS_URL: Final[str] = "https://projects.apache.org/json/foundation/groups.json"


class LDAPProjectsData(pydantic.BaseModel):
    last_timestamp: str = pydantic.Field(alias="lastTimestamp")
    project_count: int
    projects: Annotated[list[LDAPProject], util.DictToList(key="name")]

    @property
    def last_time(self) -> datetime.datetime:
        return datetime.datetime.strptime(self.last_timestamp, "%Y%m%d%H%M%S%z")


class LDAPProject(pydantic.BaseModel):
    name: str
    create_timestamp: str = pydantic.Field(alias="createTimestamp")
    modify_timestamp: str = pydantic.Field(alias="modifyTimestamp")
    member_count: int
    owner_count: int
    members: list[str]
    owners: list[str]
    pmc: bool = False
    podling: str | None = None


class User(pydantic.BaseModel):
    id: str
    name: str
    date: str | None = None


class Committee(pydantic.BaseModel):
    name: str
    display_name: str
    site: str | None
    description: str | None
    mail_list: str
    established: str | None
    report: list[str]
    chair: Annotated[list[User], util.DictToList(key="id")]
    roster_count: int
    roster: Annotated[list[User], util.DictToList(key="id")]
    pmc: bool


class CommitteeData(pydantic.BaseModel):
    last_updated: str
    committee_count: int
    pmc_count: int
    committees: Annotated[list[Committee], util.DictToList(key="name")]


class RetiredCommittee(pydantic.BaseModel):
    name: str
    display_name: str
    retired: str
    description: str | None


class RetiredCommitteeData(pydantic.BaseModel):
    last_updated: str
    retired_count: int
    retired: Annotated[list[RetiredCommittee], util.DictToList(key="name")]


class PodlingStatus(pydantic.BaseModel):
    description: str
    homepage: str
    name: str = pydantic.Field(alias="name")
    pmc: str
    podling: bool
    started: str
    champion: str | None = None
    retiring: bool | None = None
    resolution: str | None = None


class PodlingsData(util.DictRootModel[PodlingStatus]):
    pass


class GroupsData(util.DictRootModel[list[str]]):
    pass


class Release(pydantic.BaseModel):
    created: str | None = None
    name: str
    revision: str | None = None


class ProjectStatus(pydantic.BaseModel):
    category: str | None = None
    created: str | None = None
    description: str | None = None
    programming_language: str | None = pydantic.Field(alias="programming-language", default=None)
    doap: str
    homepage: str
    name: str
    pmc: str
    shortdesc: str | None = None
    repository: list[str | dict] = pydantic.Field(default_factory=list)
    release: list[Release] = pydantic.Field(default_factory=list)


class ProjectsData(util.DictRootModel[ProjectStatus]):
    pass


async def get_active_committee_data() -> CommitteeData:
    """Returns the list of currently active committees."""

    async with httpx.AsyncClient() as client:
        response = await client.get(_WHIMSY_COMMITTEE_INFO_URL)
        response.raise_for_status()
        data = response.json()

    return CommitteeData.model_validate(data)


async def get_current_podlings_data() -> PodlingsData:
    """Returns the list of current podlings."""

    async with httpx.AsyncClient() as client:
        response = await client.get(_PROJECTS_PODLINGS_URL)
        response.raise_for_status()
        data = response.json()
    return PodlingsData.model_validate(data)


async def get_groups_data() -> GroupsData:
    """Returns LDAP Groups with their members."""

    async with httpx.AsyncClient() as client:
        response = await client.get(_PROJECTS_GROUPS_URL)
        response.raise_for_status()
        data = response.json()
    return GroupsData.model_validate(data)


async def get_ldap_projects_data() -> LDAPProjectsData:
    async with httpx.AsyncClient() as client:
        response = await client.get(_WHIMSY_PROJECTS_URL)
        response.raise_for_status()
        data = response.json()

    return LDAPProjectsData.model_validate(data)


async def get_projects_data() -> ProjectsData:
    """Returns the list of projects."""

    async with httpx.AsyncClient() as client:
        response = await client.get(_PROJECTS_PROJECTS_URL)
        response.raise_for_status()
        data = response.json()
    return ProjectsData.model_validate(data)


async def get_retired_committee_data() -> RetiredCommitteeData:
    """Returns the list of retired committees."""

    async with httpx.AsyncClient() as client:
        response = await client.get(_WHIMSY_COMMITTEE_RETIRED_URL)
        response.raise_for_status()
        data = response.json()

    return RetiredCommitteeData.model_validate(data)
