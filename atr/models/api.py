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


class KeysAddArgs(schema.Strict):
    asfuid: str
    key: str
    committees: str


class KeysAddResults(schema.Strict):
    endpoint: Literal["/keys/add"] = schema.Field(alias="endpoint")
    success: str
    fingerprints: list[str]


@dataclasses.dataclass
class KeysQuery:
    offset: int = 0
    limit: int = 20


class KeysResults(schema.Strict):
    endpoint: Literal["/keys"] = schema.Field(alias="endpoint")
    data: Sequence[sql.PublicSigningKey]
    count: int


class KeysCommitteeResults(schema.Strict):
    endpoint: Literal["/keys/committee"] = schema.Field(alias="endpoint")
    keys: Sequence[sql.PublicSigningKey]


class KeysGetResults(schema.Strict):
    endpoint: Literal["/keys/get"] = schema.Field(alias="endpoint")
    key: sql.PublicSigningKey


class KeysUserResults(schema.Strict):
    endpoint: Literal["/keys/user"] = schema.Field(alias="endpoint")
    keys: Sequence[sql.PublicSigningKey]


class ProjectResults(schema.Strict):
    endpoint: Literal["/project"] = schema.Field(alias="endpoint")
    project: sql.Project


class ProjectReleasesResults(schema.Strict):
    endpoint: Literal["/project/releases"] = schema.Field(alias="endpoint")
    releases: Sequence[sql.Release]


class ProjectsResults(schema.Strict):
    endpoint: Literal["/projects"] = schema.Field(alias="endpoint")
    projects: Sequence[sql.Project]


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


class ReleasesVersionResults(schema.Strict):
    endpoint: Literal["/releases/version"] = schema.Field(alias="endpoint")
    release: sql.Release


class ReleasesRevisionsResults(schema.Strict):
    endpoint: Literal["/releases/revisions"] = schema.Field(alias="endpoint")
    revisions: Sequence[sql.Revision]


class RevisionsResults(schema.Strict):
    endpoint: Literal["/revisions"] = schema.Field(alias="endpoint")
    revisions: Sequence[sql.Revision]


class SshAddArgs(schema.Strict):
    text: str


class SshAddResults(schema.Strict):
    endpoint: Literal["/ssh/add"] = schema.Field(alias="endpoint")
    fingerprint: str


class SshDeleteArgs(schema.Strict):
    fingerprint: str


class SshDeleteResults(schema.Strict):
    endpoint: Literal["/ssh/delete"] = schema.Field(alias="endpoint")
    success: str


@dataclasses.dataclass
class SshListQuery:
    offset: int = 0
    limit: int = 20


class SshListResults(schema.Strict):
    endpoint: Literal["/ssh/list"] = schema.Field(alias="endpoint")
    data: Sequence[sql.SSHKey]
    count: int


@dataclasses.dataclass
class TasksQuery:
    limit: int = 20
    offset: int = 0
    status: str | None = None


class TasksResults(schema.Strict):
    endpoint: Literal["/tasks"] = schema.Field(alias="endpoint")
    data: Sequence[sql.Task]
    count: int


class UsersListResults(schema.Strict):
    endpoint: Literal["/users/list"] = schema.Field(alias="endpoint")
    users: Sequence[str]


class VoteResolveArgs(schema.Strict):
    project: str
    version: str
    resolution: Literal["passed", "failed"]


class VoteResolveResults(schema.Strict):
    endpoint: Literal["/vote/resolve"] = schema.Field(alias="endpoint")
    success: str


class VoteStartArgs(schema.Strict):
    project: str
    version: str
    revision: str
    email_to: str
    vote_duration: int
    subject: str
    body: str


class VoteStartResults(schema.Strict):
    endpoint: Literal["/vote/start"] = schema.Field(alias="endpoint")
    task: sql.Task


class UploadArgs(schema.Strict):
    project: str
    version: str
    relpath: str
    content: str


class UploadResults(schema.Strict):
    endpoint: Literal["/upload"] = schema.Field(alias="endpoint")
    revision: sql.Revision


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
    | KeysResults
    | KeysAddResults
    | KeysGetResults
    | KeysCommitteeResults
    | KeysUserResults
    | ListResults
    | ProjectResults
    | ProjectReleasesResults
    | ProjectsResults
    | ReleasesResults
    | ReleasesCreateResults
    | ReleasesDeleteResults
    | ReleasesProjectResults
    | ReleasesVersionResults
    | ReleasesRevisionsResults
    | RevisionsResults
    | SshAddResults
    | SshDeleteResults
    | SshListResults
    | TasksResults
    | UsersListResults
    | VoteResolveResults
    | VoteStartResults
    | UploadResults,
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
validate_keys = validator(KeysResults)
validate_keys_add = validator(KeysAddResults)
validate_keys_committee = validator(KeysCommitteeResults)
validate_keys_get = validator(KeysGetResults)
validate_keys_user = validator(KeysUserResults)
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
validate_revisions = validator(RevisionsResults)
validate_ssh_add = validator(SshAddResults)
validate_ssh_delete = validator(SshDeleteResults)
validate_ssh_list = validator(SshListResults)
validate_tasks = validator(TasksResults)
validate_users_list = validator(UsersListResults)
validate_vote_resolve = validator(VoteResolveResults)
validate_vote_start = validator(VoteStartResults)
validate_upload = validator(UploadResults)
