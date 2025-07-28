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

from . import schema, sql, tabulate

T = TypeVar("T")


def example(value: Any) -> dict[Literal["json_schema_extra"], dict[str, Any]]:
    return {"json_schema_extra": {"example": value}}


class ResultsTypeError(TypeError):
    pass


class AnnounceArgs(schema.Strict):
    project: str = schema.Field(..., **example("example"))
    version: str = schema.Field(..., **example("1.0.0"))
    revision: str = schema.Field(..., **example("00005"))
    email_to: str = schema.Field(..., **example("dev@example.apache.org"))
    subject: str = schema.Field(..., **example("[ANNOUNCE] Apache Example 1.0.0 release"))
    body: str = schema.Field(
        ...,
        **example("The Apache Example team is pleased to announce the release of Example 1.0.0..."),
    )
    path_suffix: str = schema.Field(..., **example("example/1.0.0"))


class AnnounceResults(schema.Strict):
    endpoint: Literal["/announce"] = schema.Field(alias="endpoint")
    success: str = schema.Field(..., **example("Announcement sent"))


class ChecksListResults(schema.Strict):
    endpoint: Literal["/checks/list"] = schema.Field(alias="endpoint")
    checks: Sequence[sql.CheckResult]
    checks_revision: str = schema.Field(..., **example("00005"))
    current_phase: sql.ReleasePhase = schema.Field(..., **example(sql.ReleasePhase.RELEASE_CANDIDATE))

    @pydantic.field_validator("current_phase", mode="before")
    @classmethod
    def current_phase_to_enum(cls, v):
        return sql.ReleasePhase(v) if isinstance(v, str) else v


class ChecksOngoingResults(schema.Strict):
    endpoint: Literal["/checks/ongoing"] = schema.Field(alias="endpoint")
    ongoing: int


class CommitteesGetResults(schema.Strict):
    endpoint: Literal["/committees/get"] = schema.Field(alias="endpoint")
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


@dataclasses.dataclass
class KeysQuery:
    offset: int = 0
    limit: int = 20


class KeysResults(schema.Strict):
    endpoint: Literal["/keys"] = schema.Field(alias="endpoint")
    data: Sequence[sql.PublicSigningKey]
    count: int


class KeysAddArgs(schema.Strict):
    asfuid: str
    key: str
    committees: list[str]


class KeysAddResults(schema.Strict):
    endpoint: Literal["/keys/add"] = schema.Field(alias="endpoint")
    success: str
    fingerprint: str


# class KeysCommitteeResults(schema.Strict):
#     endpoint: Literal["/keys/committee"] = schema.Field(alias="endpoint")
#     keys: Sequence[sql.PublicSigningKey]


class KeysDeleteArgs(schema.Strict):
    fingerprint: str


class KeysDeleteResults(schema.Strict):
    endpoint: Literal["/keys/delete"] = schema.Field(alias="endpoint")
    success: str


class KeysGetResults(schema.Strict):
    endpoint: Literal["/keys/get"] = schema.Field(alias="endpoint")
    key: sql.PublicSigningKey


class KeysUploadArgs(schema.Strict):
    filetext: str
    committee: str


class KeysUploadException(schema.Strict):
    status: Literal["error"] = schema.Field(alias="status")
    key: sql.PublicSigningKey | None
    error: str
    error_type: str


class KeysUploadResult(schema.Strict):
    status: Literal["success"] = schema.Field(alias="status")
    key: sql.PublicSigningKey


KeysUploadOutcome = Annotated[
    KeysUploadResult | KeysUploadException,
    schema.Field(discriminator="status"),
]

KeysUploadOutcomeAdapter = pydantic.TypeAdapter(KeysUploadOutcome)


# def validate_keys_upload_outcome(value: Any) -> KeysUploadOutcome:
#     obj = KeysUploadOutcomeAdapter.validate_python(value)
#     if not isinstance(obj, KeysUploadOutcome):
#         raise ResultsTypeError(f"Invalid API response: {value}")
#     return obj


class KeysUploadResults(schema.Strict):
    endpoint: Literal["/keys/upload"] = schema.Field(alias="endpoint")
    results: Sequence[KeysUploadResult | KeysUploadException]
    success_count: int
    error_count: int
    submitted_committee: str


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

    @pydantic.field_validator("release", mode="before")
    @classmethod
    def _preserve_latest_revision_number(cls, v):
        if isinstance(v, dict):
            data = dict(v)
            lrn = data.pop("latest_revision_number", None)
            allowed = {k: data[k] for k in data if k in sql.Release.model_fields}
            obj = sql.Release(**allowed)
            if lrn is not None:
                setattr(obj, "_latest_revision_number", lrn)
            return obj
        return v


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


class VoteTabulateArgs(schema.Strict):
    project: str
    version: str


class VoteTabulateResults(schema.Strict):
    endpoint: Literal["/vote/tabulate"] = schema.Field(alias="endpoint")
    details: tabulate.VoteDetails


class UploadArgs(schema.Strict):
    project: str
    version: str
    relpath: str
    content: str


class UploadResults(schema.Strict):
    endpoint: Literal["/upload"] = schema.Field(alias="endpoint")
    revision: sql.Revision


class VerifyProvenanceArgs(schema.Strict):
    artifact_file_name: str
    artifact_sha3_256: str
    signature_file_name: str
    signature_asc_text: str
    signature_sha3_256: str


class VerifyProvenanceKey(schema.Strict):
    committee: str
    keys_file_url: str
    keys_file_sha3_256: str


class VerifyProvenanceResults(schema.Strict):
    endpoint: Literal["/verify/provenance"] = schema.Field(alias="endpoint")
    fingerprint: str
    key_asc_text: str
    committees_with_artifact: list[VerifyProvenanceKey]


# This is for *Results classes only
# We do NOT put *Args classes here
Results = Annotated[
    AnnounceResults
    | ChecksListResults
    | ChecksOngoingResults
    | CommitteesGetResults
    | CommitteesKeysResults
    | CommitteesListResults
    | CommitteesProjectsResults
    | DraftDeleteResults
    | JwtResults
    | KeysResults
    | KeysAddResults
    | KeysDeleteResults
    | KeysGetResults
    # | KeysCommitteeResults
    | KeysUploadResults
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
    | VerifyProvenanceResults
    | VoteResolveResults
    | VoteStartResults
    | VoteTabulateResults
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
validate_committees_get = validator(CommitteesGetResults)
validate_committees_keys = validator(CommitteesKeysResults)
validate_committees_list = validator(CommitteesListResults)
validate_committees_projects = validator(CommitteesProjectsResults)
validate_draft_delete = validator(DraftDeleteResults)
validate_jwt = validator(JwtResults)
validate_keys = validator(KeysResults)
validate_keys_add = validator(KeysAddResults)
# validate_keys_committee = validator(KeysCommitteeResults)
validate_keys_delete = validator(KeysDeleteResults)
validate_keys_get = validator(KeysGetResults)
validate_keys_upload = validator(KeysUploadResults)
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
validate_verify_provenance = validator(VerifyProvenanceResults)
validate_vote_resolve = validator(VoteResolveResults)
validate_vote_start = validator(VoteStartResults)
validate_vote_tabulate = validator(VoteTabulateResults)
validate_upload = validator(UploadResults)
