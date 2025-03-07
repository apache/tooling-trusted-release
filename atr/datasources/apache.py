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

from datetime import datetime
from typing import TYPE_CHECKING, Annotated, TypeVar

import httpx
from pydantic import BaseModel, Field, RootModel

from atr.util import DictToList

if TYPE_CHECKING:
    from collections.abc import Generator, ItemsView

_WHIMSY_COMMITTEE_INFO_URL = "https://whimsy.apache.org/public/committee-info.json"
_WHIMSY_COMMITTEE_RETIRED_URL = "https://whimsy.apache.org/public/committee-retired.json"
_WHIMSY_PROJECTS_URL = "https://whimsy.apache.org/public/public_ldap_projects.json"
_PROJECTS_PROJECTS_URL = "https://projects.apache.org/json/foundation/projects.json"
_PROJECTS_PODLINGS_URL = "https://projects.apache.org/json/foundation/podlings.json"
_PROJECTS_GROUPS_URL = "https://projects.apache.org/json/foundation/groups.json"

VT = TypeVar("VT")


class LDAPProjectsData(BaseModel):
    last_timestamp: str = Field(alias="lastTimestamp")
    project_count: int
    projects: Annotated[list[LDAPProject], DictToList(key="name")]

    @property
    def last_time(self) -> datetime:
        return datetime.strptime(self.last_timestamp, "%Y%m%d%H%M%S%z")


class LDAPProject(BaseModel):
    name: str
    create_timestamp: str = Field(alias="createTimestamp")
    modify_timestamp: str = Field(alias="modifyTimestamp")
    member_count: int
    owner_count: int
    members: list[str]
    owners: list[str]
    pmc: bool = False
    podling: str | None = None


class CommitteeData(BaseModel):
    last_updated: str
    committee_count: int
    pmc_count: int
    committees: Annotated[list[Committee], DictToList(key="name")]


class RetiredCommitteeData(BaseModel):
    last_updated: str
    retired_count: int
    retired: Annotated[list[RetiredCommittee], DictToList(key="name")]


class Committee(BaseModel):
    name: str
    display_name: str
    site: str
    description: str
    mail_list: str
    established: str
    report: list[str]
    chair: Annotated[list[User], DictToList(key="id")]
    roster_count: int
    roster: Annotated[list[User], DictToList(key="id")]
    pmc: bool


class User(BaseModel):
    id: str
    name: str
    date: str | None = None


class RetiredCommittee(BaseModel):
    name: str
    display_name: str
    retired: str
    description: str


class PodlingStatus(BaseModel):
    description: str
    homepage: str
    name: str = Field(alias="name")
    pmc: str
    podling: bool
    started: str
    champion: str | None = None
    retiring: bool | None = None
    resolution: str | None = None


class _DictRootModel(RootModel[dict[str, VT]]):
    def __iter__(self) -> Generator[tuple[str, VT]]:
        yield from self.root.items()

    def items(self) -> ItemsView[str, VT]:
        return self.root.items()

    def get(self, key: str) -> VT | None:
        return self.root.get(key)

    def __len__(self) -> int:
        return len(self.root)


class PodlingsData(_DictRootModel[PodlingStatus]):
    pass


class GroupsData(_DictRootModel[list[str]]):
    pass


class Release(BaseModel):
    created: str | None = None
    name: str
    revision: str | None = None


class ProjectStatus(BaseModel):
    category: str | None = None
    created: str | None = None
    description: str | None = None
    doap: str
    homepage: str
    name: str
    pmc: str
    shortdesc: str | None = None
    repository: list[str | dict] = Field(default_factory=list)
    release: list[Release] = Field(default_factory=list)


class ProjectsData(_DictRootModel[ProjectStatus]):
    pass


async def get_ldap_projects_data() -> LDAPProjectsData:
    async with httpx.AsyncClient() as client:
        response = await client.get(_WHIMSY_PROJECTS_URL)
        response.raise_for_status()
        data = response.json()

    return LDAPProjectsData.model_validate(data)


async def get_active_committee_data() -> CommitteeData:
    """Returns the list of currently active committees."""

    async with httpx.AsyncClient() as client:
        response = await client.get(_WHIMSY_COMMITTEE_INFO_URL)
        response.raise_for_status()
        data = response.json()

    return CommitteeData.model_validate(data)


async def get_retired_committee_data() -> RetiredCommitteeData:
    """Returns the list of retired committees."""

    async with httpx.AsyncClient() as client:
        response = await client.get(_WHIMSY_COMMITTEE_RETIRED_URL)
        response.raise_for_status()
        data = response.json()

    return RetiredCommitteeData.model_validate(data)


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


async def get_projects_data() -> ProjectsData:
    """Returns the list of projects."""

    async with httpx.AsyncClient() as client:
        response = await client.get(_PROJECTS_PROJECTS_URL)
        response.raise_for_status()
        data = response.json()
    return ProjectsData.model_validate(data)
