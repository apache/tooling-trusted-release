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
from typing import TYPE_CHECKING, Annotated, Any, Final

if TYPE_CHECKING:
    from collections.abc import Mapping

import aiohttp
import sqlmodel

import atr.db as db
import atr.log as log
import atr.models.helpers as helpers
import atr.models.schema as schema
import atr.models.sql as sql
import atr.util as util

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
    next_board_meetings: dict[str, Any] = schema.alias_opt("nextBoardMeetings")


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


async def update_metadata() -> tuple[int, int]:
    """Update metadata from remote data sources."""

    ldap_projects = await get_ldap_projects_data()
    projects = await get_projects_data()
    podlings_data = await get_current_podlings_data()
    committees = await get_active_committee_data()

    ldap_projects_by_name: Mapping[str, LDAPProject] = {p.name: p for p in ldap_projects.projects}
    committees_by_name: Mapping[str, Committee] = {c.name: c for c in committees.committees}

    added_count = 0
    updated_count = 0

    async with db.session() as data:
        async with data.begin():
            added, updated = await _update_committees(data, ldap_projects, committees_by_name)
            added_count += added
            updated_count += updated

            added, updated = await _update_podlings(data, podlings_data, ldap_projects_by_name)
            added_count += added
            updated_count += updated

            added, updated = await _update_projects(data, projects)
            added_count += added
            updated_count += updated

            added, updated = await _update_tooling(data)
            added_count += added
            updated_count += updated

            added, updated = await _process_undiscovered(data)
            added_count += added
            updated_count += updated

    return added_count, updated_count


def _project_status(pmc: sql.Committee, project_name: str, project_status: ProjectStatus) -> sql.ProjectStatus:
    if pmc.name == "attic":
        # This must come first, because attic is also a standing committee
        return sql.ProjectStatus.RETIRED
    elif ("_dormant_" in project_name) or project_status.name.endswith("(Dormant)"):
        return sql.ProjectStatus.DORMANT
    elif util.committee_is_standing(pmc.name):
        return sql.ProjectStatus.STANDING
    return sql.ProjectStatus.ACTIVE


async def _process_undiscovered(data: db.Session) -> tuple[int, int]:
    added_count = 0
    updated_count = 0

    via = sql.validate_instrumented_attribute
    committees_without_projects = await db.Query(
        data, sqlmodel.select(sql.Committee).where(~via(sql.Committee.projects).any())
    ).all()
    # For all committees that have no associated projects
    for committee in committees_without_projects:
        if committee.name == "incubator":
            continue
        log.warning(f"Missing top level project for committee {committee.name}")
        # If a committee is missing, the following code can be activated to fix it
        # But ideally the fix should be in the upstream data source
        # project = sql.Project(
        #     name=committee.name,
        #     full_name=committee.full_name,
        #     committee=committee,
        # )
        # data.add(project)
        # added_count += 1

    return added_count, updated_count


async def _update_committees(
    data: db.Session, ldap_projects: LDAPProjectsData, committees_by_name: Mapping[str, Committee]
) -> tuple[int, int]:
    added_count = 0
    updated_count = 0

    # First create PMC committees
    for project in ldap_projects.projects:
        name = project.name
        # Skip non-PMC committees
        if project.pmc is not True:
            continue

        # Get or create PMC
        committee = await data.committee(name=name).get()
        if not committee:
            committee = sql.Committee(name=name)
            data.add(committee)
            added_count += 1
        else:
            updated_count += 1

        committee.committee_members = project.owners
        committee.committers = project.members
        # We create PMCs for now
        committee.is_podling = False
        committee_info = committees_by_name.get(name)
        if committee_info:
            committee.full_name = committee_info.display_name

        updated_count += 1

    return added_count, updated_count


async def _update_podlings(
    data: db.Session, podlings_data: PodlingsData, ldap_projects_by_name: Mapping[str, LDAPProject]
) -> tuple[int, int]:
    added_count = 0
    updated_count = 0

    # Then add PPMCs and their associated project (podlings)
    for podling_name, podling_data in podlings_data:
        # Get or create PPMC
        ppmc = await data.committee(name=podling_name).get()
        if not ppmc:
            ppmc = sql.Committee(name=podling_name, is_podling=True)
            data.add(ppmc)
            added_count += 1
        else:
            updated_count += 1

        # We create a PPMC
        ppmc.is_podling = True
        ppmc.full_name = podling_data.name.removesuffix("(Incubating)").removeprefix("Apache").strip()
        podling_project = ldap_projects_by_name.get(podling_name)
        if podling_project is not None:
            ppmc.committee_members = podling_project.owners
            ppmc.committers = podling_project.members
        else:
            log.warning(f"could not find ldap data for podling {podling_name}")

        podling = await data.project(name=podling_name).get()
        if not podling:
            # Create the associated podling project
            podling = sql.Project(name=podling_name, full_name=podling_data.name, committee=ppmc)
            data.add(podling)
            added_count += 1
        else:
            updated_count += 1

        podling.full_name = podling_data.name.removesuffix(" (Incubating)")
        podling.committee = ppmc
        # TODO: Why did the type checkers not detect this?
        # podling.is_podling = True

    return added_count, updated_count


async def _update_projects(data: db.Session, projects: ProjectsData) -> tuple[int, int]:
    added_count = 0
    updated_count = 0

    # Add projects and associate them with the right PMC
    for project_name, project_status in projects.items():
        # FIXME: this is a quick workaround for inconsistent data wrt webservices PMC / projects
        #        the PMC seems to be identified by the key ws, but the associated projects use webservices
        if project_name.startswith("webservices-"):
            project_name = project_name.replace("webservices-", "ws-")
            project_status.pmc = "ws"

        # TODO: Annotator is in both projects and ldap_projects
        # The projects version is called "incubator-annotator", with "incubator" as its pmc
        # This is not detected by us as incubating, because we create those above
        # ("Create the associated podling project")
        # Since the Annotator project is in ldap_projects, we can just skip it here
        # Originally reported in https://github.com/apache/tooling-trusted-releases/issues/35
        # Ideally it would be removed from the upstream data source, which is:
        # https://projects.apache.org/json/foundation/projects.json
        if project_name == "incubator-annotator":
            continue

        pmc = await data.committee(name=project_status.pmc).get()
        if not pmc:
            log.warning(f"could not find PMC for project {project_name}: {project_status.pmc}")
            continue

        project_model = await data.project(name=project_name).get()
        # Check whether the project is retired, whether temporarily or otherwise
        status = _project_status(pmc, project_name, project_status)
        if not project_model:
            project_model = sql.Project(name=project_name, committee=pmc, status=status)
            data.add(project_model)
            added_count += 1
        else:
            project_model.status = status
            updated_count += 1

        project_model.full_name = project_status.name
        project_model.category = project_status.category
        project_model.description = project_status.description
        project_model.programming_languages = project_status.programming_language

    return added_count, updated_count


async def _update_tooling(data: db.Session) -> tuple[int, int]:
    added_count = 0
    updated_count = 0

    # Tooling is not a committee
    # We add a special entry for Tooling, pretending to be a PMC, for debugging and testing
    tooling_committee = await data.committee(name="tooling").get()
    if not tooling_committee:
        tooling_committee = sql.Committee(name="tooling", full_name="Tooling")
        data.add(tooling_committee)
        tooling_project = sql.Project(name="tooling", full_name="Apache Tooling", committee=tooling_committee)
        data.add(tooling_project)
        added_count += 1
    else:
        updated_count += 1

    # Update Tooling PMC data
    # Could put this in the "if not tooling_committee" block, perhaps
    tooling_committee.committee_members = ["wave", "tn", "sbp"]
    tooling_committee.committers = ["wave", "tn", "sbp"]
    tooling_committee.release_managers = ["wave"]
    tooling_committee.is_podling = False

    return added_count, updated_count
