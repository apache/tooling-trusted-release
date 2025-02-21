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

from collections.abc import Generator, ItemsView
from datetime import datetime
from typing import Annotated

import httpx
from pydantic import BaseModel, Field, RootModel

from atr.util import DictToList

_WHIMSY_COMMITTEE_INFO_URL = "https://whimsy.apache.org/public/committee-info.json"
_WHIMSY_COMMITTEE_RETIRED_URL = "https://whimsy.apache.org/public/committee-retired.json"
_WHIMSY_PROJECTS_URL = "https://whimsy.apache.org/public/public_ldap_projects.json"
_PROJECT_PODLINGS_URL = "https://projects.apache.org/json/foundation/podlings.json"
_PROJECT_GROUPS_URL = "https://projects.apache.org/json/foundation/groups.json"


class LDAPProjects(BaseModel):
    last_timestamp: str = Field(alias="lastTimestamp")
    project_count: int
    projects: Annotated[list[Project], DictToList(key="name")]

    @property
    def last_time(self) -> datetime:
        return datetime.strptime(self.last_timestamp, "%Y%m%d%H%M%S%z")


class Project(BaseModel):
    name: str
    createTimestamp: str
    modifyTimestamp: str
    member_count: int
    owner_count: int
    members: list[str]
    owners: list[str]
    pmc: bool = False
    podling: str | None = None


class CommitteeInfo(BaseModel):
    last_updated: str
    committee_count: int
    pmc_count: int
    committees: Annotated[list[Committee], DictToList(key="name")]


class CommitteeRetired(BaseModel):
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
    # chair: Annotated[list[User], DictToList(key="id")]
    roster_count: int
    roster: Annotated[list[User], DictToList(key="id")]
    pmc: bool


class User(BaseModel):
    id: str
    name: str
    date: str


class RetiredCommittee(BaseModel):
    name: str
    display_name: str
    retired: str
    description: str


class PodlingStatus(BaseModel):
    description: str
    homepage: str
    name: str
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


class GroupsData(RootModel):
    root: dict[str, list[str]]

    def __iter__(self) -> Generator[tuple[str, list[str]]]:
        yield from self.root.items()

    def items(self) -> ItemsView[str, list[str]]:
        return self.root.items()

    def get(self, key: str) -> list[str] | None:
        return self.root.get(key)


async def get_ldap_projects_data() -> LDAPProjects:
    async with httpx.AsyncClient() as client:
        response = await client.get(_WHIMSY_PROJECTS_URL)
        response.raise_for_status()
        data = response.json()

    return LDAPProjects.model_validate(data)


async def get_committee_info_data() -> CommitteeInfo:
    async with httpx.AsyncClient() as client:
        response = await client.get(_WHIMSY_COMMITTEE_INFO_URL)
        response.raise_for_status()
        data = response.json()

    return CommitteeInfo.model_validate(data)


async def get_committee_retired_data() -> CommitteeRetired:
    async with httpx.AsyncClient() as client:
        response = await client.get(_WHIMSY_COMMITTEE_RETIRED_URL)
        response.raise_for_status()
        data = response.json()

    return CommitteeRetired.model_validate(data)


async def get_podlings_data() -> PodlingsData:
    async with httpx.AsyncClient() as client:
        response = await client.get(_PROJECT_PODLINGS_URL)
        response.raise_for_status()
        data = response.json()
    return PodlingsData(root=data)


async def get_groups_data() -> GroupsData:
    async with httpx.AsyncClient() as client:
        response = await client.get(_PROJECT_GROUPS_URL)
        response.raise_for_status()
        data = response.json()
    return GroupsData(root=data)
