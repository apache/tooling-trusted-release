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


class ResultsTypeError(TypeError):
    pass


class ChecksListResults(schema.Strict):
    endpoint: Literal["/checks/list"] = schema.alias("endpoint")
    checks: Sequence[sql.CheckResult]
    checks_revision: str = schema.example("00005")
    current_phase: sql.ReleasePhase = schema.example(sql.ReleasePhase.RELEASE_CANDIDATE)

    @pydantic.field_validator("current_phase", mode="before")
    @classmethod
    def current_phase_to_enum(cls, v):
        return sql.ReleasePhase(v) if isinstance(v, str) else v


class ChecksOngoingResults(schema.Strict):
    endpoint: Literal["/checks/ongoing"] = schema.alias("endpoint")
    ongoing: int = schema.example(10)


class CommitteeGetResults(schema.Strict):
    endpoint: Literal["/committee/get"] = schema.alias("endpoint")
    committee: sql.Committee


class CommitteeKeysResults(schema.Strict):
    endpoint: Literal["/committee/keys"] = schema.alias("endpoint")
    keys: Sequence[sql.PublicSigningKey]


class CommitteeProjectsResults(schema.Strict):
    endpoint: Literal["/committee/projects"] = schema.alias("endpoint")
    projects: Sequence[sql.Project]


class CommitteesListResults(schema.Strict):
    endpoint: Literal["/committees/list"] = schema.alias("endpoint")
    committees: Sequence[sql.Committee]


class DistributionRecordArgs(schema.Strict):
    project: str = schema.example("example")
    version: str = schema.example("0.0.1")
    platform: sql.DistributionPlatform = schema.example(sql.DistributionPlatform.ARTIFACT_HUB)
    distribution_owner_namespace: str | None = schema.default_example(None, "example")
    distribution_package: str = schema.example("example")
    distribution_version: str = schema.example("0.0.1")
    staging: bool = schema.example(False)
    details: bool = schema.example(False)

    @pydantic.field_validator("platform", mode="before")
    @classmethod
    def platform_to_enum(cls, v):
        if isinstance(v, str):
            try:
                return sql.DistributionPlatform.__members__[v]
            except KeyError:
                raise ValueError(f"'{v}' is not a valid DistributionPlatform")
        return v

    @pydantic.field_serializer("platform")
    def serialise_platform(self, v):
        return v.name if isinstance(v, sql.DistributionPlatform) else v


class DistributionRecordResults(schema.Strict):
    endpoint: Literal["/distribution/record"] = schema.alias("endpoint")
    success: Literal[True] = schema.example(True)


class IgnoreAddArgs(schema.Strict):
    committee_name: str = schema.example("example")
    release_glob: str | None = schema.default_example(None, "example-0.0.*")
    revision_number: str | None = schema.default_example(None, "00001")
    checker_glob: str | None = schema.default_example(None, "atr.tasks.checks.license.files")
    primary_rel_path_glob: str | None = schema.default_example(None, "apache-example-0.0.1-*.tar.gz")
    member_rel_path_glob: str | None = schema.default_example(None, "apache-example-0.0.1/*.xml")
    status: sql.CheckResultStatusIgnore | None = schema.default_example(None, sql.CheckResultStatusIgnore.FAILURE)
    message_glob: str | None = schema.default_example(None, "sha512 matches for apache-example-0.0.1/*.xml")


class IgnoreAddResults(schema.Strict):
    endpoint: Literal["/ignore/add"] = schema.alias("endpoint")
    success: Literal[True] = schema.example(True)


class IgnoreDeleteArgs(schema.Strict):
    committee: str = schema.example("example")
    id: int = schema.example(1)


class IgnoreDeleteResults(schema.Strict):
    endpoint: Literal["/ignore/delete"] = schema.alias("endpoint")
    success: Literal[True] = schema.example(True)


class IgnoreListResults(schema.Strict):
    endpoint: Literal["/ignore/list"] = schema.alias("endpoint")
    ignores: Sequence[sql.CheckResultIgnore]


class JwtCreateArgs(schema.Strict):
    asfuid: str = schema.example("user")
    pat: str = schema.example("8M5t4GCU63EdOy4NNXgXn7o-bc-muK8TRg5W-DeBaWY")


class JwtCreateResults(schema.Strict):
    endpoint: Literal["/jwt/create"] = schema.alias("endpoint")
    asfuid: str = schema.example("user")
    jwt: str = schema.example("eyJhbGciOiJIUzI1[...]mMjLiuyu5CSpyHI=")


class KeyAddArgs(schema.Strict):
    asfuid: str = schema.example("user")
    key: str = schema.example("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n...\n-----END PGP PUBLIC KEY BLOCK-----\n")
    committees: list[str] = schema.example(["example"])


class KeyAddResults(schema.Strict):
    endpoint: Literal["/key/add"] = schema.alias("endpoint")
    fingerprint: str = schema.example("0123456789abcdef0123456789abcdef01234567")


class KeyDeleteArgs(schema.Strict):
    fingerprint: str = schema.example("0123456789abcdef0123456789abcdef01234567")


class KeyDeleteResults(schema.Strict):
    endpoint: Literal["/key/delete"] = schema.alias("endpoint")
    success: Literal[True] = schema.example(True)


class KeyGetResults(schema.Strict):
    endpoint: Literal["/key/get"] = schema.alias("endpoint")
    key: sql.PublicSigningKey


class KeysUploadArgs(schema.Strict):
    filetext: str = schema.example("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n...\n-----END PGP PUBLIC KEY BLOCK-----\n")
    committee: str = schema.example("example")


class KeysUploadException(schema.Strict):
    status: Literal["error"] = schema.alias("status")
    key: sql.PublicSigningKey | None
    error: str = schema.example("Error message")
    error_type: str = schema.example("KeysUploadError")


class KeysUploadResult(schema.Strict):
    status: Literal["success"] = schema.alias("status")
    key: sql.PublicSigningKey


type KeysUploadOutcome = Annotated[
    KeysUploadResult | KeysUploadException,
    schema.discriminator("status"),
]

KeysUploadOutcomeAdapter = pydantic.TypeAdapter(KeysUploadOutcome)


class KeysUploadResults(schema.Strict):
    endpoint: Literal["/keys/upload"] = schema.alias("endpoint")
    results: Sequence[KeysUploadResult | KeysUploadException]
    success_count: int = schema.example(1)
    error_count: int = schema.example(0)
    submitted_committee: str = schema.example("example")


class KeysUserResults(schema.Strict):
    endpoint: Literal["/keys/user"] = schema.alias("endpoint")
    keys: Sequence[sql.PublicSigningKey]


class ProjectGetResults(schema.Strict):
    endpoint: Literal["/project/get"] = schema.alias("endpoint")
    project: sql.Project


class ProjectReleasesResults(schema.Strict):
    endpoint: Literal["/project/releases"] = schema.alias("endpoint")
    releases: Sequence[sql.Release]


class ProjectsListResults(schema.Strict):
    endpoint: Literal["/projects/list"] = schema.alias("endpoint")
    projects: Sequence[sql.Project]


class PublisherDistributionRecordArgs(schema.Strict):
    publisher: str = schema.example("user")
    jwt: str = schema.example("eyJhbGciOiJIUzI1[...]mMjLiuyu5CSpyHI=")
    version: str = schema.example("0.0.1")
    platform: sql.DistributionPlatform = schema.example(sql.DistributionPlatform.ARTIFACT_HUB)
    distribution_owner_namespace: str | None = schema.default_example(None, "example")
    distribution_package: str = schema.example("example")
    distribution_version: str = schema.example("0.0.1")
    staging: bool = schema.example(False)
    details: bool = schema.example(False)

    @pydantic.field_validator("platform", mode="before")
    @classmethod
    def platform_to_enum(cls, v):
        if isinstance(v, str):
            try:
                return sql.DistributionPlatform.__members__[v]
            except KeyError:
                raise ValueError(f"'{v}' is not a valid DistributionPlatform")
        return v

    @pydantic.field_serializer("platform")
    def serialise_platform(self, v):
        return v.name if isinstance(v, sql.DistributionPlatform) else v


class PublisherDistributionRecordResults(schema.Strict):
    endpoint: Literal["/publisher/distribution/record"] = schema.alias("endpoint")
    success: Literal[True] = schema.example(True)


class PublisherReleaseAnnounceArgs(schema.Strict):
    publisher: str = schema.example("user")
    jwt: str = schema.example("eyJhbGciOiJIUzI1[...]mMjLiuyu5CSpyHI=")
    version: str = schema.example("0.0.1")
    revision: str = schema.example("00005")
    email_to: str = schema.example("dev@example.apache.org")
    subject: str = schema.example("[ANNOUNCE] Apache Example 1.0.0 release")
    body: str = schema.example("The Apache Example team is pleased to announce the release of Example 1.0.0...")
    path_suffix: str = schema.example("example/1.0.0")


class PublisherReleaseAnnounceResults(schema.Strict):
    endpoint: Literal["/publisher/release/announce"] = schema.alias("endpoint")
    success: Literal[True] = schema.example(True)


class PublisherSshRegisterArgs(schema.Strict):
    publisher: str = schema.example("user")
    jwt: str = schema.example("eyJhbGciOiJIUzI1[...]mMjLiuyu5CSpyHI=")
    ssh_key: str = schema.example("ssh-ed25519 AAAAC3NzaC1lZDI1NTEgH5C9okWi0dh25AAAAIOMqqnkVzrm0SdG6UOoqKLsabl9GKJl")


class PublisherSshRegisterResults(schema.Strict):
    endpoint: Literal["/publisher/ssh/register"] = schema.alias("endpoint")
    fingerprint: str = schema.example("SHA256:0123456789abcdef0123456789abcdef01234567")
    project: str = schema.example("example")
    expires: int = schema.example(1713547200)


class PublisherVoteResolveArgs(schema.Strict):
    publisher: str = schema.example("user")
    jwt: str = schema.example("eyJhbGciOiJIUzI1[...]mMjLiuyu5CSpyHI=")
    version: str = schema.example("0.0.1")
    resolution: Literal["passed", "failed"] = schema.example("passed")


class PublisherVoteResolveResults(schema.Strict):
    endpoint: Literal["/publisher/vote/resolve"] = schema.alias("endpoint")
    success: Literal[True] = schema.example(True)


class ReleaseAnnounceArgs(schema.Strict):
    project: str = schema.example("example")
    version: str = schema.example("1.0.0")
    revision: str = schema.example("00005")
    email_to: str = schema.example("dev@example.apache.org")
    subject: str = schema.example("[ANNOUNCE] Apache Example 1.0.0 release")
    body: str = schema.example("The Apache Example team is pleased to announce the release of Example 1.0.0...")
    path_suffix: str = schema.example("example/1.0.0")


class ReleaseAnnounceResults(schema.Strict):
    endpoint: Literal["/release/announce"] = schema.alias("endpoint")
    success: Literal[True] = schema.example(True)


class ReleaseDraftDeleteArgs(schema.Strict):
    project: str = schema.example("example")
    version: str = schema.example("0.0.1")


class ReleaseDraftDeleteResults(schema.Strict):
    endpoint: Literal["/release/draft/delete"] = schema.alias("endpoint")
    success: Literal[True] = schema.example(True)


class ReleaseCreateArgs(schema.Strict):
    project: str = schema.example("example")
    version: str = schema.example("0.0.1")


class ReleaseCreateResults(schema.Strict):
    endpoint: Literal["/release/create"] = schema.alias("endpoint")
    release: sql.Release


class ReleaseDeleteArgs(schema.Strict):
    project: str = schema.example("example")
    version: str = schema.example("0.0.1")


class ReleaseDeleteResults(schema.Strict):
    endpoint: Literal["/release/delete"] = schema.alias("endpoint")
    deleted: Literal[True] = schema.example(True)


class ReleaseGetResults(schema.Strict):
    endpoint: Literal["/release/get"] = schema.alias("endpoint")
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
    endpoint: Literal["/release/paths"] = schema.alias("endpoint")
    rel_paths: Sequence[str] = schema.example(["example/0.0.1/example-0.0.1-bin.tar.gz"])


class ReleaseRevisionsResults(schema.Strict):
    endpoint: Literal["/release/revisions"] = schema.alias("endpoint")
    revisions: Sequence[sql.Revision]


class ReleaseUploadArgs(schema.Strict):
    project: str = schema.example("example")
    version: str = schema.example("0.0.1")
    relpath: str = schema.example("example/0.0.1/example-0.0.1-bin.tar.gz")
    content: str = schema.example("This is the content of the file.")


class ReleaseUploadResults(schema.Strict):
    endpoint: Literal["/release/upload"] = schema.alias("endpoint")
    revision: sql.Revision


@dataclasses.dataclass
class ReleasesListQuery:
    offset: int = 0
    limit: int = 20
    phase: str | None = None


class ReleasesListResults(schema.Strict):
    endpoint: Literal["/releases/list"] = schema.alias("endpoint")
    data: Sequence[sql.Release]
    count: int


class SignatureProvenanceArgs(schema.Strict):
    artifact_file_name: str = schema.example("example-0.0.1-bin.tar.gz")
    artifact_sha3_256: str = schema.example("0123456789abcdef0123456789abcdef01234567")
    signature_file_name: str = schema.example("example-0.0.1-bin.tar.gz.asc")
    signature_asc_text: str = schema.example("-----BEGIN PGP SIGNATURE-----\n\n...\n-----END PGP SIGNATURE-----\n")
    signature_sha3_256: str = schema.example("0123456789abcdef0123456789abcdef01234567")


class SignatureProvenanceKey(schema.Strict):
    committee: str = schema.example("example")
    keys_file_url: str = schema.example("https://example.apache.org/example/KEYS")
    keys_file_sha3_256: str = schema.example("0123456789abcdef0123456789abcdef01234567")


class SignatureProvenanceResults(schema.Strict):
    endpoint: Literal["/signature/provenance"] = schema.alias("endpoint")
    fingerprint: str = schema.example("0123456789abcdef0123456789abcdef01234567")
    key_asc_text: str = schema.example(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n...\n-----END PGP PUBLIC KEY BLOCK-----\n"
    )
    committees_with_artifact: list[SignatureProvenanceKey]


class SshKeyAddArgs(schema.Strict):
    text: str = schema.example("ssh-ed25519 AAAAC3NzaC1lZDI1NTEgH5C9okWi0dh25AAAAIOMqqnkVzrm0SdG6UOoqKLsabl9GKJl")


class SshKeyAddResults(schema.Strict):
    endpoint: Literal["/ssh-key/add"] = schema.alias("endpoint")
    fingerprint: str = schema.example("0123456789abcdef0123456789abcdef01234567")


class SshKeyDeleteArgs(schema.Strict):
    fingerprint: str = schema.example("0123456789abcdef0123456789abcdef01234567")


class SshKeyDeleteResults(schema.Strict):
    endpoint: Literal["/ssh-key/delete"] = schema.alias("endpoint")
    success: Literal[True] = schema.example(True)


@dataclasses.dataclass
class SshKeysListQuery:
    offset: int = 0
    limit: int = 20


class SshKeysListResults(schema.Strict):
    endpoint: Literal["/ssh-keys/list"] = schema.alias("endpoint")
    data: Sequence[sql.SSHKey]
    count: int = schema.example(10)


@dataclasses.dataclass
class TasksListQuery:
    limit: int = 20
    offset: int = 0
    status: str | None = None


class TasksListResults(schema.Strict):
    endpoint: Literal["/tasks/list"] = schema.alias("endpoint")
    data: Sequence[sql.Task]
    count: int = schema.example(10)


class UserInfoResults(schema.Strict):
    endpoint: Literal["/user/info"] = schema.alias("endpoint")
    participant_of: list[str] = schema.example(["committee_name_a", "committee_name_b"])
    member_of: list[str] = schema.example(["committee_name_a"])


class UsersListResults(schema.Strict):
    endpoint: Literal["/users/list"] = schema.alias("endpoint")
    users: Sequence[str] = schema.example(["user1", "user2"])


class VoteResolveArgs(schema.Strict):
    project: str = schema.example("example")
    version: str = schema.example("0.0.1")
    resolution: Literal["passed", "failed"] = schema.example("passed")


class VoteResolveResults(schema.Strict):
    endpoint: Literal["/vote/resolve"] = schema.alias("endpoint")
    success: Literal[True] = schema.example(True)


class VoteStartArgs(schema.Strict):
    project: str = schema.example("example")
    version: str = schema.example("0.0.1")
    revision: str = schema.example("00005")
    email_to: str = schema.example("dev@example.apache.org")
    vote_duration: int = schema.example(10)
    subject: str = schema.example("[VOTE] Apache Example 0.0.1 release")
    body: str = schema.example("The Apache Example team is pleased to announce the release of Example 0.0.1...")


class VoteStartResults(schema.Strict):
    endpoint: Literal["/vote/start"] = schema.alias("endpoint")
    task: sql.Task


class VoteTabulateArgs(schema.Strict):
    project: str = schema.example("example")
    version: str = schema.example("0.0.1")


class VoteTabulateResults(schema.Strict):
    endpoint: Literal["/vote/tabulate"] = schema.alias("endpoint")
    details: tabulate.VoteDetails


# This is for *Results classes only
# We do NOT put *Args classes here
type Results = Annotated[
    ChecksListResults
    | ChecksOngoingResults
    | CommitteeGetResults
    | CommitteeKeysResults
    | CommitteeProjectsResults
    | CommitteesListResults
    | DistributionRecordResults
    | IgnoreAddResults
    | IgnoreDeleteResults
    | IgnoreListResults
    | JwtCreateResults
    | KeyAddResults
    | KeyDeleteResults
    | KeyGetResults
    | KeysUploadResults
    | KeysUserResults
    | ProjectGetResults
    | ProjectReleasesResults
    | ProjectsListResults
    | PublisherDistributionRecordResults
    | PublisherReleaseAnnounceResults
    | PublisherSshRegisterResults
    | PublisherVoteResolveResults
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
    | UserInfoResults
    | UsersListResults
    | VoteResolveResults
    | VoteStartResults
    | VoteTabulateResults,
    schema.discriminator("endpoint"),
]

ResultsAdapter = pydantic.TypeAdapter(Results)


def validator[T](t: type[T]) -> Callable[[Any], T]:
    def validate(value: Any) -> T:
        obj = ResultsAdapter.validate_python(value)
        if not isinstance(obj, t):
            raise ResultsTypeError(f"Invalid API response: {value}")
        return obj

    return validate


validate_checks_list = validator(ChecksListResults)
validate_checks_ongoing = validator(ChecksOngoingResults)
validate_committee_get = validator(CommitteeGetResults)
validate_committee_keys = validator(CommitteeKeysResults)
validate_committee_projects = validator(CommitteeProjectsResults)
validate_committees_list = validator(CommitteesListResults)
validate_distribution_record = validator(DistributionRecordResults)
validate_ignore_add = validator(IgnoreAddResults)
validate_ignore_delete = validator(IgnoreDeleteResults)
validate_ignore_list = validator(IgnoreListResults)
validate_jwt_create = validator(JwtCreateResults)
validate_key_add = validator(KeyAddResults)
validate_key_delete = validator(KeyDeleteResults)
validate_key_get = validator(KeyGetResults)
validate_keys_upload = validator(KeysUploadResults)
validate_keys_user = validator(KeysUserResults)
validate_project_get = validator(ProjectGetResults)
validate_project_releases = validator(ProjectReleasesResults)
validate_projects_list = validator(ProjectsListResults)
validate_publisher_distribution_record = validator(PublisherDistributionRecordResults)
validate_publisher_release_announce = validator(PublisherReleaseAnnounceResults)
validate_publisher_ssh_register = validator(PublisherSshRegisterResults)
validate_publisher_vote_resolve = validator(PublisherVoteResolveResults)
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
validate_user_info = validator(UserInfoResults)
validate_users_list = validator(UsersListResults)
validate_vote_resolve = validator(VoteResolveResults)
validate_vote_start = validator(VoteStartResults)
validate_vote_tabulate = validator(VoteTabulateResults)
