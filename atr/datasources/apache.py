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
from typing import TYPE_CHECKING, Annotated

import httpx
from pydantic import BaseModel, Field, RootModel

from atr.util import DictToList

if TYPE_CHECKING:
    from collections.abc import Generator, ItemsView

_WHIMSY_COMMITTEE_INFO_URL = "https://whimsy.apache.org/public/committee-info.json"
_WHIMSY_COMMITTEE_RETIRED_URL = "https://whimsy.apache.org/public/committee-retired.json"
_WHIMSY_PROJECTS_URL = "https://whimsy.apache.org/public/public_ldap_projects.json"
_PROJECT_PODLINGS_URL = "https://projects.apache.org/json/foundation/podlings.json"
_PROJECT_GROUPS_URL = "https://projects.apache.org/json/foundation/groups.json"


class ProjectData(BaseModel):
    last_timestamp: str = Field(alias="lastTimestamp")
    project_count: int
    projects: Annotated[list[Project], DictToList(key="name")]

    @property
    def last_time(self) -> datetime:
        return datetime.strptime(self.last_timestamp, "%Y%m%d%H%M%S%z")


class Project(BaseModel):
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


class PodlingsData(RootModel):
    root: dict[str, PodlingStatus]

    def __iter__(self) -> Generator[tuple[str, PodlingStatus]]:
        yield from self.root.items()

    def items(self) -> ItemsView[str, PodlingStatus]:
        return self.root.items()

    def get(self, key: str) -> PodlingStatus | None:
        return self.root.get(key)

    def __len__(self) -> int:
        return len(self.root)


class GroupsData(RootModel):
    root: dict[str, list[str]]

    def __iter__(self) -> Generator[tuple[str, list[str]]]:
        yield from self.root.items()

    def items(self) -> ItemsView[str, list[str]]:
        return self.root.items()

    def get(self, key: str) -> list[str] | None:
        return self.root.get(key)

    def __len__(self) -> int:
        return len(self.root)


async def get_projects_data() -> ProjectData:
    async with httpx.AsyncClient() as client:
        response = await client.get(_WHIMSY_PROJECTS_URL)
        response.raise_for_status()
        data = response.json()

    return ProjectData.model_validate(data)


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
        response = await client.get(_PROJECT_PODLINGS_URL)
        response.raise_for_status()
        data = response.json()
    return PodlingsData(root=data)


async def get_groups_data() -> GroupsData:
    """Returns LDAP Groups with their members."""

    async with httpx.AsyncClient() as client:
        response = await client.get(_PROJECT_GROUPS_URL)
        response.raise_for_status()
        data = response.json()
    return GroupsData(root=data)
