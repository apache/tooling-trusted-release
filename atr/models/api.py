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
from collections.abc import Callable, Sequence
from typing import Annotated, Any, Literal, TypeVar

import pydantic

from . import schema, sql

T = TypeVar("T")


class ResultsTypeError(TypeError):
    pass


@dataclasses.dataclass
class Pagination:
    offset: int = 0
    limit: int = 20


# TODO: TaskPagination?
@dataclasses.dataclass
class Task(Pagination):
    status: str | None = None


class AnnounceArgs(schema.Strict):
    project: str
    version: str
    revision: str
    email_to: str
    subject: str
    body: str
    path_suffix: str


class AnnounceResults(schema.Strict):
    endpoint: Literal["/announce"] = schema.Field(alias="endpoint")
    success: str


class ChecksListResults(schema.Strict):
    endpoint: Literal["/checks/list"] = schema.Field(alias="endpoint")
    checks: Sequence[sql.CheckResult]


class ChecksOngoingResults(schema.Strict):
    endpoint: Literal["/checks/ongoing"] = schema.Field(alias="endpoint")
    ongoing: int


class CommitteesResults(schema.Strict):
    endpoint: Literal["/committees"] = schema.Field(alias="endpoint")
    committee: sql.Committee


class CommitteesKeysResults(schema.Strict):
    endpoint: Literal["/committees/keys"] = schema.Field(alias="endpoint")
    keys: Sequence[sql.PublicSigningKey]


class CommitteesListResults(schema.Strict):
    endpoint: Literal["/committees/list"] = schema.Field(alias="endpoint")
    committees: Sequence[sql.Committee]


class CommitteesProjectsResults(schema.Strict):
    endpoint: Literal["/committees/projects"] = schema.Field(alias="endpoint")
    projects: Sequence[sql.Project]


class DraftDeleteArgs(schema.Strict):
    project: str
    version: str


class DraftDeleteResults(schema.Strict):
    endpoint: Literal["/draft/delete"] = schema.Field(alias="endpoint")
    success: str


class ListResults(schema.Strict):
    endpoint: Literal["/list"] = schema.Field(alias="endpoint")
    rel_paths: Sequence[str]


class JwtArgs(schema.Strict):
    asfuid: str
    pat: str


class JwtResults(schema.Strict):
    endpoint: Literal["/jwt"] = schema.Field(alias="endpoint")
    asfuid: str
    jwt: str


class KeyResults(schema.Strict):
    endpoint: Literal["/key"] = schema.Field(alias="endpoint")
    key: sql.PublicSigningKey


@dataclasses.dataclass
class KeysQuery:
    offset: int = 0
    limit: int = 20


class KeysResults(schema.Strict):
    endpoint: Literal["/keys"] = schema.Field(alias="endpoint")
    data: Sequence[sql.PublicSigningKey]
    count: int


class KeysSshAddArgs(schema.Strict):
    text: str


class KeysSshAddResults(schema.Strict):
    endpoint: Literal["/keys/ssh/add"] = schema.Field(alias="endpoint")
    fingerprint: str


class KeysSshListQuery(Pagination):
    offset: int = 0
    limit: int = 20


class KeysSshListResults(schema.Strict):
    endpoint: Literal["/keys/ssh/list"] = schema.Field(alias="endpoint")
    data: Sequence[sql.SSHKey]
    count: int


class ProjectResults(schema.Strict):
    endpoint: Literal["/project"] = schema.Field(alias="endpoint")
    project: sql.Project


class ProjectReleasesResults(schema.Strict):
    endpoint: Literal["/project/releases"] = schema.Field(alias="endpoint")
    releases: Sequence[sql.Release]


class ProjectsResults(schema.Strict):
    endpoint: Literal["/projects"] = schema.Field(alias="endpoint")
    projects: Sequence[sql.Project]


class ProjectVersion(schema.Strict):
    project: str
    version: str


class ProjectVersionRelpathContent(schema.Strict):
    project: str
    version: str
    relpath: str
    content: str


class ProjectVersionResolution(schema.Strict):
    project: str
    version: str
    resolution: Literal["passed", "failed"]


@dataclasses.dataclass
class ReleasesQuery:
    offset: int = 0
    limit: int = 20
    phase: str | None = None


class ReleasesResults(schema.Strict):
    endpoint: Literal["/releases"] = schema.Field(alias="endpoint")
    data: Sequence[sql.Release]
    count: int


class ReleasesCreateArgs(schema.Strict):
    project: str
    version: str


class ReleasesCreateResults(schema.Strict):
    endpoint: Literal["/releases/create"] = schema.Field(alias="endpoint")
    release: sql.Release


class ReleasesDeleteArgs(schema.Strict):
    project: str
    version: str


class ReleasesDeleteResults(schema.Strict):
    endpoint: Literal["/releases/delete"] = schema.Field(alias="endpoint")
    deleted: str


@dataclasses.dataclass
class ReleasesProjectQuery:
    limit: int = 20
    offset: int = 0
    # project: str
    # version: str


class ReleasesProjectResults(schema.Strict):
    endpoint: Literal["/releases/project"] = schema.Field(alias="endpoint")
    data: Sequence[sql.Release]
    count: int

    @pydantic.field_validator("data", mode="before")
    @classmethod
    def coerce_release(cls, v: Sequence[dict[str, Any]]) -> Sequence[sql.Release]:
        return [sql.Release.model_validate(item) if isinstance(item, dict) else item for item in v]


class ReleasesVersionResults(schema.Strict):
    endpoint: Literal["/releases/version"] = schema.Field(alias="endpoint")
    release: sql.Release


class ReleasesRevisionsResults(schema.Strict):
    endpoint: Literal["/releases/revisions"] = schema.Field(alias="endpoint")
    revisions: Sequence[sql.Revision]


class Text(schema.Strict):
    text: str


class VoteStart(schema.Strict):
    project: str
    version: str
    revision: str
    email_to: str
    vote_duration: int
    subject: str
    body: str


# This is for *Results classes only
# We do NOT put *Args classes here
Results = Annotated[
    AnnounceResults
    | ChecksListResults
    | ChecksOngoingResults
    | CommitteesResults
    | CommitteesKeysResults
    | CommitteesListResults
    | CommitteesProjectsResults
    | DraftDeleteResults
    | JwtResults
    | KeyResults
    | KeysResults
    | KeysSshAddResults
    | KeysSshListResults
    | ListResults
    | ProjectResults
    | ProjectReleasesResults
    | ProjectsResults
    | ReleasesResults
    | ReleasesCreateResults
    | ReleasesDeleteResults
    | ReleasesProjectResults
    | ReleasesVersionResults
    | ReleasesRevisionsResults,
    schema.Field(discriminator="endpoint"),
]

ResultsAdapter = pydantic.TypeAdapter(Results)


def validator[T](t: type[T]) -> Callable[[Any], T]:
    def validate(value: Any) -> T:
        obj = ResultsAdapter.validate_python(value)
        if not isinstance(obj, t):
            raise ResultsTypeError(f"Invalid API response: {value}")
        return obj

    return validate


validate_announce = validator(AnnounceResults)
validate_checks_list = validator(ChecksListResults)
validate_checks_ongoing = validator(ChecksOngoingResults)
validate_committees = validator(CommitteesResults)
validate_committees_keys = validator(CommitteesKeysResults)
validate_committees_list = validator(CommitteesListResults)
validate_committees_projects = validator(CommitteesProjectsResults)
validate_draft_delete = validator(DraftDeleteResults)
validate_jwt = validator(JwtResults)
validate_key = validator(KeyResults)
validate_keys = validator(KeysResults)
validate_keys_ssh_add = validator(KeysSshAddResults)
validate_keys_ssh_list = validator(KeysSshListResults)
validate_list = validator(ListResults)
validate_project = validator(ProjectResults)
validate_project_releases = validator(ProjectReleasesResults)
validate_projects = validator(ProjectsResults)
validate_releases = validator(ReleasesResults)
validate_releases_create = validator(ReleasesCreateResults)
validate_releases_delete = validator(ReleasesDeleteResults)
validate_releases_project = validator(ReleasesProjectResults)
validate_releases_version = validator(ReleasesVersionResults)
validate_releases_revisions = validator(ReleasesRevisionsResults)
