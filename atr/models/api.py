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


class ChecksIgnoreAddArgs(schema.Strict):
    committee_name: str = schema.Field(..., **example("example"))
    release_glob: str | None = schema.Field(default=None, **example("example-0.0.*"))
    revision_number: str | None = schema.Field(default=None, **example("00001"))
    checker_glob: str | None = schema.Field(default=None, **example("atr.tasks.checks.license.files"))
    primary_rel_path_glob: str | None = schema.Field(default=None, **example("apache-example-0.0.1-*.tar.gz"))
    member_rel_path_glob: str | None = schema.Field(default=None, **example("apache-example-0.0.1/*.xml"))
    status: sql.CheckResultStatusIgnore | None = schema.Field(
        default=None, **example(sql.CheckResultStatusIgnore.FAILURE)
    )
    message_glob: str | None = schema.Field(default=None, **example("sha512 matches for apache-example-0.0.1/*.xml"))


class ChecksIgnoreAddResults(schema.Strict):
    endpoint: Literal["/checks/ignore/add"] = schema.Field(alias="endpoint")
    success: Literal[True] = schema.Field(..., **example(True))


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
    ongoing: int = schema.Field(..., **example(10))


class CommitteeGetResults(schema.Strict):
    endpoint: Literal["/committee/get"] = schema.Field(alias="endpoint")
    committee: sql.Committee


class CommitteeKeysResults(schema.Strict):
    endpoint: Literal["/committee/keys"] = schema.Field(alias="endpoint")
    keys: Sequence[sql.PublicSigningKey]


class CommitteeProjectsResults(schema.Strict):
    endpoint: Literal["/committee/projects"] = schema.Field(alias="endpoint")
    projects: Sequence[sql.Project]


class CommitteesListResults(schema.Strict):
    endpoint: Literal["/committees/list"] = schema.Field(alias="endpoint")
    committees: Sequence[sql.Committee]


class JwtCreateArgs(schema.Strict):
    asfuid: str = schema.Field(..., **example("user"))
    pat: str = schema.Field(..., **example("8M5t4GCU63EdOy4NNXgXn7o-bc-muK8TRg5W-DeBaWY"))


class JwtCreateResults(schema.Strict):
    endpoint: Literal["/jwt/create"] = schema.Field(alias="endpoint")
    asfuid: str = schema.Field(..., **example("user"))
    jwt: str = schema.Field(..., **example("eyJhbGciOiJIUzI1[...]mMjLiuyu5CSpyHI="))


class KeyAddArgs(schema.Strict):
    asfuid: str = schema.Field(..., **example("user"))
    key: str = schema.Field(
        ..., **example("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n...\n-----END PGP PUBLIC KEY BLOCK-----\n")
    )
    committees: list[str] = schema.Field(..., **example(["example"]))


class KeyAddResults(schema.Strict):
    endpoint: Literal["/key/add"] = schema.Field(alias="endpoint")
    fingerprint: str = schema.Field(..., **example("0123456789abcdef0123456789abcdef01234567"))


class KeyDeleteArgs(schema.Strict):
    fingerprint: str = schema.Field(..., **example("0123456789abcdef0123456789abcdef01234567"))


class KeyDeleteResults(schema.Strict):
    endpoint: Literal["/key/delete"] = schema.Field(alias="endpoint")
    success: Literal[True] = schema.Field(..., **example(True))


class KeyGetResults(schema.Strict):
    endpoint: Literal["/key/get"] = schema.Field(alias="endpoint")
    key: sql.PublicSigningKey


class KeysUploadArgs(schema.Strict):
    filetext: str = schema.Field(
        ..., **example("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n...\n-----END PGP PUBLIC KEY BLOCK-----\n")
    )
    committee: str = schema.Field(..., **example("example"))


class KeysUploadException(schema.Strict):
    status: Literal["error"] = schema.Field(alias="status")
    key: sql.PublicSigningKey | None
    error: str = schema.Field(..., **example("Error message"))
    error_type: str = schema.Field(..., **example("KeysUploadError"))


class KeysUploadResult(schema.Strict):
    status: Literal["success"] = schema.Field(alias="status")
    key: sql.PublicSigningKey


KeysUploadOutcome = Annotated[
    KeysUploadResult | KeysUploadException,
    schema.Field(discriminator="status"),
]

KeysUploadOutcomeAdapter = pydantic.TypeAdapter(KeysUploadOutcome)


class KeysUploadResults(schema.Strict):
    endpoint: Literal["/keys/upload"] = schema.Field(alias="endpoint")
    results: Sequence[KeysUploadResult | KeysUploadException]
    success_count: int = schema.Field(..., **example(1))
    error_count: int = schema.Field(..., **example(0))
    submitted_committee: str = schema.Field(..., **example("example"))


class KeysUserResults(schema.Strict):
    endpoint: Literal["/keys/user"] = schema.Field(alias="endpoint")
    keys: Sequence[sql.PublicSigningKey]


class ProjectGetResults(schema.Strict):
    endpoint: Literal["/project/get"] = schema.Field(alias="endpoint")
    project: sql.Project


class ProjectReleasesResults(schema.Strict):
    endpoint: Literal["/project/releases"] = schema.Field(alias="endpoint")
    releases: Sequence[sql.Release]


class ProjectsListResults(schema.Strict):
    endpoint: Literal["/projects/list"] = schema.Field(alias="endpoint")
    projects: Sequence[sql.Project]


class ReleaseAnnounceArgs(schema.Strict):
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


class ReleaseAnnounceResults(schema.Strict):
    endpoint: Literal["/release/announce"] = schema.Field(alias="endpoint")
    success: Literal[True] = schema.Field(..., **example(True))


class ReleaseDraftDeleteArgs(schema.Strict):
    project: str = schema.Field(..., **example("example"))
    version: str = schema.Field(..., **example("0.0.1"))


class ReleaseDraftDeleteResults(schema.Strict):
    endpoint: Literal["/release/draft/delete"] = schema.Field(alias="endpoint")
    success: Literal[True] = schema.Field(..., **example(True))


class ReleaseCreateArgs(schema.Strict):
    project: str = schema.Field(..., **example("example"))
    version: str = schema.Field(..., **example("0.0.1"))


class ReleaseCreateResults(schema.Strict):
    endpoint: Literal["/release/create"] = schema.Field(alias="endpoint")
    release: sql.Release


class ReleaseDeleteArgs(schema.Strict):
    project: str = schema.Field(..., **example("example"))
    version: str = schema.Field(..., **example("0.0.1"))


class ReleaseDeleteResults(schema.Strict):
    endpoint: Literal["/release/delete"] = schema.Field(alias="endpoint")
    deleted: Literal[True] = schema.Field(..., **example(True))


class ReleaseGetResults(schema.Strict):
    endpoint: Literal["/release/get"] = schema.Field(alias="endpoint")
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


class ReleasePathsResults(schema.Strict):
    endpoint: Literal["/release/paths"] = schema.Field(alias="endpoint")
    rel_paths: Sequence[str] = schema.Field(..., **example(["example/0.0.1/example-0.0.1-bin.tar.gz"]))


class ReleaseRevisionsResults(schema.Strict):
    endpoint: Literal["/release/revisions"] = schema.Field(alias="endpoint")
    revisions: Sequence[sql.Revision]


class ReleaseUploadArgs(schema.Strict):
    project: str = schema.Field(..., **example("example"))
    version: str = schema.Field(..., **example("0.0.1"))
    relpath: str = schema.Field(..., **example("example/0.0.1/example-0.0.1-bin.tar.gz"))
    content: str = schema.Field(..., **example("This is the content of the file."))


class ReleaseUploadResults(schema.Strict):
    endpoint: Literal["/release/upload"] = schema.Field(alias="endpoint")
    revision: sql.Revision


@dataclasses.dataclass
class ReleasesListQuery:
    offset: int = 0
    limit: int = 20
    phase: str | None = None


class ReleasesListResults(schema.Strict):
    endpoint: Literal["/releases/list"] = schema.Field(alias="endpoint")
    data: Sequence[sql.Release]
    count: int


class SignatureProvenanceArgs(schema.Strict):
    artifact_file_name: str = schema.Field(..., **example("example-0.0.1-bin.tar.gz"))
    artifact_sha3_256: str = schema.Field(..., **example("0123456789abcdef0123456789abcdef01234567"))
    signature_file_name: str = schema.Field(..., **example("example-0.0.1-bin.tar.gz.asc"))
    signature_asc_text: str = schema.Field(
        ..., **example("-----BEGIN PGP SIGNATURE-----\n\n...\n-----END PGP SIGNATURE-----\n")
    )
    signature_sha3_256: str = schema.Field(..., **example("0123456789abcdef0123456789abcdef01234567"))


class SignatureProvenanceKey(schema.Strict):
    committee: str = schema.Field(..., **example("example"))
    keys_file_url: str = schema.Field(..., **example("https://example.apache.org/example/KEYS"))
    keys_file_sha3_256: str = schema.Field(..., **example("0123456789abcdef0123456789abcdef01234567"))


class SignatureProvenanceResults(schema.Strict):
    endpoint: Literal["/signature/provenance"] = schema.Field(alias="endpoint")
    fingerprint: str = schema.Field(..., **example("0123456789abcdef0123456789abcdef01234567"))
    key_asc_text: str = schema.Field(
        ..., **example("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n...\n-----END PGP PUBLIC KEY BLOCK-----\n")
    )
    committees_with_artifact: list[SignatureProvenanceKey]


class SshKeyAddArgs(schema.Strict):
    text: str = schema.Field(
        ..., **example("ssh-ed25519 AAAAC3NzaC1lZDI1NTEgH5C9okWi0dh25AAAAIOMqqnkVzrm0SdG6UOoqKLsabl9GKJl")
    )


class SshKeyAddResults(schema.Strict):
    endpoint: Literal["/ssh-key/add"] = schema.Field(alias="endpoint")
    fingerprint: str = schema.Field(..., **example("0123456789abcdef0123456789abcdef01234567"))


class SshKeyDeleteArgs(schema.Strict):
    fingerprint: str = schema.Field(..., **example("0123456789abcdef0123456789abcdef01234567"))


class SshKeyDeleteResults(schema.Strict):
    endpoint: Literal["/ssh-key/delete"] = schema.Field(alias="endpoint")
    success: Literal[True] = schema.Field(..., **example(True))


@dataclasses.dataclass
class SshKeysListQuery:
    offset: int = 0
    limit: int = 20


class SshKeysListResults(schema.Strict):
    endpoint: Literal["/ssh-keys/list"] = schema.Field(alias="endpoint")
    data: Sequence[sql.SSHKey]
    count: int = schema.Field(..., **example(10))


@dataclasses.dataclass
class TasksListQuery:
    limit: int = 20
    offset: int = 0
    status: str | None = None


class TasksListResults(schema.Strict):
    endpoint: Literal["/tasks/list"] = schema.Field(alias="endpoint")
    data: Sequence[sql.Task]
    count: int = schema.Field(..., **example(10))


class UsersListResults(schema.Strict):
    endpoint: Literal["/users/list"] = schema.Field(alias="endpoint")
    users: Sequence[str] = schema.Field(..., **example(["user1", "user2"]))


class VoteResolveArgs(schema.Strict):
    project: str = schema.Field(..., **example("example"))
    version: str = schema.Field(..., **example("0.0.1"))
    resolution: Literal["passed", "failed"] = schema.Field(..., **example("passed"))


class VoteResolveResults(schema.Strict):
    endpoint: Literal["/vote/resolve"] = schema.Field(alias="endpoint")
    success: Literal[True] = schema.Field(..., **example(True))


class VoteStartArgs(schema.Strict):
    project: str = schema.Field(..., **example("example"))
    version: str = schema.Field(..., **example("0.0.1"))
    revision: str = schema.Field(..., **example("00005"))
    email_to: str = schema.Field(..., **example("dev@example.apache.org"))
    vote_duration: int = schema.Field(..., **example(10))
    subject: str = schema.Field(..., **example("[VOTE] Apache Example 0.0.1 release"))
    body: str = schema.Field(
        ..., **example("The Apache Example team is pleased to announce the release of Example 0.0.1...")
    )


class VoteStartResults(schema.Strict):
    endpoint: Literal["/vote/start"] = schema.Field(alias="endpoint")
    task: sql.Task


class VoteTabulateArgs(schema.Strict):
    project: str = schema.Field(..., **example("example"))
    version: str = schema.Field(..., **example("0.0.1"))


class VoteTabulateResults(schema.Strict):
    endpoint: Literal["/vote/tabulate"] = schema.Field(alias="endpoint")
    details: tabulate.VoteDetails


# This is for *Results classes only
# We do NOT put *Args classes here
Results = Annotated[
    ChecksIgnoreAddResults
    | ChecksListResults
    | ChecksOngoingResults
    | CommitteeGetResults
    | CommitteeKeysResults
    | CommitteeProjectsResults
    | CommitteesListResults
    | JwtCreateResults
    | KeyAddResults
    | KeyDeleteResults
    | KeyGetResults
    | KeysUploadResults
    | KeysUserResults
    | ProjectGetResults
    | ProjectReleasesResults
    | ProjectsListResults
    | ReleaseAnnounceResults
    | ReleaseCreateResults
    | ReleaseDeleteResults
    | ReleaseDraftDeleteResults
    | ReleaseGetResults
    | ReleasePathsResults
    | ReleaseRevisionsResults
    | ReleaseUploadResults
    | ReleasesListResults
    | SignatureProvenanceResults
    | SshKeyAddResults
    | SshKeyDeleteResults
    | SshKeysListResults
    | TasksListResults
    | UsersListResults
    | VoteResolveResults
    | VoteStartResults
    | VoteTabulateResults,
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


validate_checks_ignore_add = validator(ChecksIgnoreAddResults)
validate_checks_list = validator(ChecksListResults)
validate_checks_ongoing = validator(ChecksOngoingResults)
validate_committee_get = validator(CommitteeGetResults)
validate_committee_keys = validator(CommitteeKeysResults)
validate_committee_projects = validator(CommitteeProjectsResults)
validate_committees_list = validator(CommitteesListResults)
validate_jwt_create = validator(JwtCreateResults)
validate_key_add = validator(KeyAddResults)
validate_key_delete = validator(KeyDeleteResults)
validate_key_get = validator(KeyGetResults)
validate_keys_upload = validator(KeysUploadResults)
validate_keys_user = validator(KeysUserResults)
validate_project_get = validator(ProjectGetResults)
validate_project_releases = validator(ProjectReleasesResults)
validate_projects_list = validator(ProjectsListResults)
validate_release_announce = validator(ReleaseAnnounceResults)
validate_release_create = validator(ReleaseCreateResults)
validate_release_delete = validator(ReleaseDeleteResults)
validate_release_draft_delete = validator(ReleaseDraftDeleteResults)
validate_release_get = validator(ReleaseGetResults)
validate_release_paths = validator(ReleasePathsResults)
validate_release_revisions = validator(ReleaseRevisionsResults)
validate_release_upload = validator(ReleaseUploadResults)
validate_releases_list = validator(ReleasesListResults)
validate_signature_provenance = validator(SignatureProvenanceResults)
validate_ssh_key_add = validator(SshKeyAddResults)
validate_ssh_key_delete = validator(SshKeyDeleteResults)
validate_ssh_keys_list = validator(SshKeysListResults)
validate_tasks_list = validator(TasksListResults)
validate_users_list = validator(UsersListResults)
validate_vote_resolve = validator(VoteResolveResults)
validate_vote_start = validator(VoteStartResults)
validate_vote_tabulate = validator(VoteTabulateResults)
