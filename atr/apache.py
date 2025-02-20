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

from typing import Annotated

import httpx
from pydantic import BaseModel

from atr.util import DictToList

_WHIMSY_COMMITTEE_URL = "https://whimsy.apache.org/public/committee-info.json"
_WHIMSY_PROJECTS_URL = "https://whimsy.apache.org/public/public_ldap_projects.json"


class ApacheProjects(BaseModel):
    lastTimestamp: str
    project_count: int
    projects: Annotated[list[ApacheProject], DictToList(key="name")]


class ApacheProject(BaseModel):
    name: str
    createTimestamp: str
    modifyTimestamp: str
    member_count: int
    owner_count: int
    members: list[str]
    owners: list[str]
    pmc: bool = False
    podling: str | None = None


async def get_apache_project_data() -> ApacheProjects:
    async with httpx.AsyncClient() as client:
        response = await client.get(_WHIMSY_PROJECTS_URL)
        response.raise_for_status()
        data = response.json()

    return ApacheProjects.model_validate(data)
