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

"""The data models to be persisted in the database."""

# NOTE: We can't use symbolic annotations here because sqlmodel doesn't support them
# https://github.com/fastapi/sqlmodel/issues/196
# https://github.com/fastapi/sqlmodel/pull/778/files

import dataclasses
import datetime
import enum
from typing import Any, Final, Literal, Optional, TypeVar

import pydantic
import sqlalchemy
import sqlalchemy.event as event
import sqlalchemy.orm as orm
import sqlalchemy.sql.expression as expression
import sqlmodel

from . import results, schema

T = TypeVar("T")

sqlmodel.SQLModel.metadata = sqlalchemy.MetaData(
    naming_convention={
        "ix": "ix_%(table_name)s_%(column_0_N_name)s",
        "uq": "uq_%(table_name)s_%(column_0_N_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)

# Data classes


@dataclasses.dataclass(frozen=True)
class DistributionPlatformValue:
    name: str
    template_url: str
    template_staging_url: str | None = None
    requires_owner_namespace: bool = False
    default_owner_namespace: str | None = None


# Enumerations


class CheckResultStatus(str, enum.Enum):
    EXCEPTION = "exception"
    FAILURE = "failure"
    SUCCESS = "success"
    WARNING = "warning"


class CheckResultStatusIgnore(str, enum.Enum):
    EXCEPTION = "exception"
    FAILURE = "failure"
    WARNING = "warning"

    @classmethod
    def from_form_field(cls, status: str) -> Optional["CheckResultStatusIgnore"]:
        match status:
            case "None":
                return None
            case "CheckResultStatusIgnore.EXCEPTION":
                return cls.EXCEPTION
            case "CheckResultStatusIgnore.FAILURE":
                return cls.FAILURE
            case "CheckResultStatusIgnore.WARNING":
                return cls.WARNING
            case _:
                raise ValueError(f"Invalid status: {status}")

    def to_form_field(self) -> str:
        return f"CheckResultStatusIgnore.{self.value.upper()}"


class DistributionPlatform(enum.Enum):
    ARTIFACT_HUB = DistributionPlatformValue(
        name="Artifact Hub",
        template_url="https://artifacthub.io/api/v1/packages/helm/{owner_namespace}/{package}/{version}",
        template_staging_url="https://staging.artifacthub.io/api/v1/packages/helm/{owner_namespace}/{package}/{version}",
        requires_owner_namespace=True,
    )
    DOCKER_HUB = DistributionPlatformValue(
        name="Docker Hub",
        template_url="https://hub.docker.com/v2/namespaces/{owner_namespace}/repositories/{package}/tags/{version}",
        # TODO: Need to use staging tags?
        # template_staging_url="https://hub.docker.com/v2/namespaces/{owner_namespace}/repositories/{package}/tags/{version}",
        default_owner_namespace="library",
    )
    # GITHUB = DistributionPlatformValue(
    #     name="GitHub",
    #     template_url="https://api.github.com/repos/{owner_namespace}/{package}/releases/tags/v{version}",
    #     # Combine with {"prerelease": true}
    #     template_staging_url="https://api.github.com/repos/{owner_namespace}/{package}/releases",
    #     requires_owner_namespace=True,
    # )
    MAVEN = DistributionPlatformValue(
        name="Maven Central",
        template_url="https://search.maven.org/solrsearch/select?q=g:{owner_namespace}+AND+a:{package}+AND+v:{version}&core=gav&rows=20&wt=json",
        # Java ASF projects use staging URLs along the lines of
        # https://repository.apache.org/content/repositories/orgapachePROJECT-NNNN/
        # There's no JSON, but each individual package has maven-metadata.xml
        requires_owner_namespace=True,
    )
    NPM = DistributionPlatformValue(
        name="npm",
        # TODO: Need to parse dist-tags
        template_url="https://registry.npmjs.org/{package}",
    )
    NPM_SCOPED = DistributionPlatformValue(
        name="npm (scoped)",
        # TODO: Need to parse dist-tags
        template_url="https://registry.npmjs.org/@{owner_namespace}/{package}",
        requires_owner_namespace=True,
    )
    PYPI = DistributionPlatformValue(
        name="PyPI",
        template_url="https://pypi.org/pypi/{package}/{version}/json",
        template_staging_url="https://test.pypi.org/pypi/{package}/{version}/json",
    )


class ProjectStatus(str, enum.Enum):
    ACTIVE = "active"
    DORMANT = "dormant"
    RETIRED = "retired"
    STANDING = "standing"


class ReleasePhase(str, enum.Enum):
    # TODO: Rename these to the UI names?
    # COMPOSE, VOTE, FINISH, "DISTRIBUTE"
    # Compose a draft
    # Vote on a candidate
    # Finish a preview
    # Distribute a (finished) release
    # Step 1: The candidate files are added from external sources and checked by ATR
    RELEASE_CANDIDATE_DRAFT = "release_candidate_draft"
    # Step 2: The project members are voting on the candidate release
    RELEASE_CANDIDATE = "release_candidate"
    # Step 3: The release files are being put in place
    RELEASE_PREVIEW = "release_preview"
    # Step 4: The release has been announced
    RELEASE = "release"


class TaskStatus(str, enum.Enum):
    """Status of a task in the task queue."""

    QUEUED = "queued"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskType(str, enum.Enum):
    HASHING_CHECK = "hashing_check"
    KEYS_IMPORT_FILE = "keys_import_file"
    LICENSE_FILES = "license_files"
    LICENSE_HEADERS = "license_headers"
    MESSAGE_SEND = "message_send"
    METADATA_UPDATE = "metadata_update"
    PATHS_CHECK = "paths_check"
    RAT_CHECK = "rat_check"
    SBOM_AUGMENT = "sbom_augment"
    SBOM_GENERATE_CYCLONEDX = "sbom_generate_cyclonedx"
    SBOM_OSV_SCAN = "sbom_osv_scan"
    SBOM_QS_SCORE = "sbom_qs_score"
    SBOM_TOOL_SCORE = "sbom_tool_score"
    SIGNATURE_CHECK = "signature_check"
    SVN_IMPORT_FILES = "svn_import_files"
    TARGZ_INTEGRITY = "targz_integrity"
    TARGZ_STRUCTURE = "targz_structure"
    VOTE_INITIATE = "vote_initiate"
    ZIPFORMAT_INTEGRITY = "zipformat_integrity"
    ZIPFORMAT_STRUCTURE = "zipformat_structure"


class UserRole(str, enum.Enum):
    COMMITTEE_MEMBER = "committee_member"
    RELEASE_MANAGER = "release_manager"
    COMMITTER = "committer"
    VISITOR = "visitor"
    ASF_MEMBER = "asf_member"
    SYSADMIN = "sysadmin"


# Pydantic models


def pydantic_example(value: Any) -> dict[Literal["json_schema_extra"], dict[str, Any]]:
    return {"json_schema_extra": {"example": value}}


class VoteEntry(schema.Strict):
    result: bool = schema.Field(alias="result", **pydantic_example(True))
    summary: str = schema.Field(alias="summary", **pydantic_example("This is a summary"))
    binding_votes: int = schema.Field(alias="binding_votes", **pydantic_example(10))
    community_votes: int = schema.Field(alias="community_votes", **pydantic_example(10))
    start: datetime.datetime = schema.Field(
        alias="start", **pydantic_example(datetime.datetime(2025, 5, 5, 1, 2, 3, tzinfo=datetime.UTC))
    )
    end: datetime.datetime = schema.Field(
        alias="end", **pydantic_example(datetime.datetime(2025, 5, 7, 1, 2, 3, tzinfo=datetime.UTC))
    )


# Type decorators
# TODO: Possibly move these to a separate module
# That way, we can more easily track Alembic's dependence on them


class UTCDateTime(sqlalchemy.types.TypeDecorator):
    """
    A custom column type to store datetime in sqlite.

    As sqlite does not have timezone support, we ensure that all datetimes stored
    within sqlite are converted to UTC. When retrieved, the datetimes are constructed
    as offset-aware datetime with UTC as their timezone.
    """

    impl = sqlalchemy.types.TIMESTAMP(timezone=True)

    cache_ok = True

    def process_bind_param(self, value, dialect):  # type: ignore
        if value:
            if not isinstance(value, datetime.datetime):
                raise ValueError(f"Unexpected value type {type(value)}")

            if value.tzinfo is None:
                raise ValueError("Unexpected offset-naive datetime")

            # store the datetime in UTC in sqlite as it does not support timezones
            return value.astimezone(datetime.UTC)
        else:
            return value

    def process_result_value(self, value, dialect):  # type: ignore
        if isinstance(value, datetime.datetime):
            return value.replace(tzinfo=datetime.UTC)
        else:
            return value


class ResultsJSON(sqlalchemy.types.TypeDecorator):
    impl = sqlalchemy.JSON
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if hasattr(value, "model_dump"):
            return value.model_dump()
        if isinstance(value, dict):
            return value
        raise ValueError("Unsupported value for Results column")

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        try:
            return results.ResultsAdapter.validate_python(value)
        except pydantic.ValidationError:
            # TODO: Should we make this more strict?
            return None


# SQL models


def example(value: Any) -> dict[Literal["schema_extra"], dict[str, Any]]:
    return {"schema_extra": {"json_schema_extra": {"examples": [value]}}}


# SQL models with no dependencies


# KeyLink:
class KeyLink(sqlmodel.SQLModel, table=True):
    committee_name: str = sqlmodel.Field(foreign_key="committee.name", primary_key=True)
    key_fingerprint: str = sqlmodel.Field(foreign_key="publicsigningkey.fingerprint", primary_key=True)


# PersonalAccessToken:
class PersonalAccessToken(sqlmodel.SQLModel, table=True):
    id: int | None = sqlmodel.Field(default=None, primary_key=True)
    asfuid: str = sqlmodel.Field(index=True)
    token_hash: str = sqlmodel.Field(unique=True)
    created: datetime.datetime = sqlmodel.Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC), sa_column=sqlalchemy.Column(UTCDateTime)
    )
    expires: datetime.datetime = sqlmodel.Field(sa_column=sqlalchemy.Column(UTCDateTime))
    last_used: datetime.datetime | None = sqlmodel.Field(default=None, sa_column=sqlalchemy.Column(UTCDateTime))
    label: str | None = None


# SSHKey:
class SSHKey(sqlmodel.SQLModel, table=True):
    fingerprint: str = sqlmodel.Field(primary_key=True)
    key: str
    asf_uid: str


# Task:
class Task(sqlmodel.SQLModel, table=True):
    """A task in the task queue."""

    id: int = sqlmodel.Field(default=None, primary_key=True)
    status: TaskStatus = sqlmodel.Field(default=TaskStatus.QUEUED, index=True)
    task_type: TaskType
    task_args: Any = sqlmodel.Field(sa_column=sqlalchemy.Column(sqlalchemy.JSON))
    asf_uid: str
    added: datetime.datetime = sqlmodel.Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC),
        sa_column=sqlalchemy.Column(UTCDateTime, index=True),
    )
    started: datetime.datetime | None = sqlmodel.Field(
        default=None,
        sa_column=sqlalchemy.Column(UTCDateTime),
    )
    pid: int | None = None
    completed: datetime.datetime | None = sqlmodel.Field(
        default=None,
        sa_column=sqlalchemy.Column(UTCDateTime),
    )
    result: results.Results | None = sqlmodel.Field(default=None, sa_column=sqlalchemy.Column(ResultsJSON))
    error: str | None = None

    # Used for check tasks
    # We don't put these in task_args because we want to query them efficiently
    project_name: str | None = sqlmodel.Field(default=None, foreign_key="project.name")
    version_name: str | None = sqlmodel.Field(default=None, index=True)
    revision_number: str | None = sqlmodel.Field(default=None, index=True)
    primary_rel_path: str | None = sqlmodel.Field(default=None, index=True)

    def model_post_init(self, _context):
        if isinstance(self.task_type, str):
            self.task_type = TaskType(self.task_type)

        if isinstance(self.status, str):
            self.status = TaskStatus(self.status)

        if isinstance(self.added, str):
            self.added = datetime.datetime.fromisoformat(self.added.rstrip("Z"))

        if isinstance(self.started, str):
            self.started = datetime.datetime.fromisoformat(self.started.rstrip("Z"))

        if isinstance(self.completed, str):
            self.completed = datetime.datetime.fromisoformat(self.completed.rstrip("Z"))

    # Create an index on status and added for efficient task claiming
    __table_args__ = (
        sqlalchemy.Index("ix_task_status_added", "status", "added"),
        # Ensure valid status transitions:
        # - QUEUED can transition to ACTIVE
        # - ACTIVE can transition to COMPLETED or FAILED
        # - COMPLETED and FAILED are terminal states
        sqlalchemy.CheckConstraint(
            """
            (
                -- Initial state is always valid
                status = 'QUEUED'
                -- QUEUED -> ACTIVE requires setting started time and pid
                OR (status = 'ACTIVE' AND started IS NOT NULL AND pid IS NOT NULL)
                -- ACTIVE -> COMPLETED requires setting completed time and result
                OR (status = 'COMPLETED' AND completed IS NOT NULL AND result IS NOT NULL)
                -- ACTIVE -> FAILED requires setting completed time and error (result optional)
                OR (status = 'FAILED' AND completed IS NOT NULL AND error IS NOT NULL)
            )
            """,
            name="valid_task_status_transitions",
        ),
    )


# TextValue:
class TextValue(sqlmodel.SQLModel, table=True):
    # Composite primary key, automatically handled by SQLModel
    ns: str = sqlmodel.Field(primary_key=True, index=True)
    key: str = sqlmodel.Field(primary_key=True, index=True)
    value: str = sqlmodel.Field()


# WorkflowSSHKey:
class WorkflowSSHKey(sqlmodel.SQLModel, table=True):
    fingerprint: str = sqlmodel.Field(primary_key=True, index=True)
    key: str = sqlmodel.Field()
    project_name: str = sqlmodel.Field(index=True)
    asf_uid: str = sqlmodel.Field(index=True)
    github_uid: str = sqlmodel.Field(index=True)
    github_nid: int = sqlmodel.Field(index=True)
    expires: int = sqlmodel.Field()


# SQL core models


# Committee: Committee Project PublicSigningKey
class Committee(sqlmodel.SQLModel, table=True):
    # TODO: Consider using key or label for primary string keys
    # Then we can use simply "name" for full_name, and make it str rather than str | None
    name: str = sqlmodel.Field(unique=True, primary_key=True, **example("example"))
    full_name: str | None = sqlmodel.Field(default=None, **example("Example"))
    # True only if this is an incubator podling with a PPMC
    is_podling: bool = sqlmodel.Field(default=False)

    # 1-M: Committee -> [Committee]
    # M-1: Committee -> Committee
    child_committees: list["Committee"] = sqlmodel.Relationship(
        sa_relationship_kwargs=dict(
            backref=orm.backref("parent_committee", remote_side="Committee.name"),
        ),
    )

    # M-1: Committee -> Committee
    # 1-M: Committee -> [Committee]
    parent_committee_name: str | None = sqlmodel.Field(default=None, foreign_key="committee.name")
    # parent_committee: Optional["Committee"]

    # 1-M: Committee -> [Project]
    # M-1: Project -> Committee
    projects: list["Project"] = sqlmodel.Relationship(back_populates="committee")

    committee_members: list[str] = sqlmodel.Field(
        default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON), **example(["sbp", "tn", "wave"])
    )
    committers: list[str] = sqlmodel.Field(
        default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON), **example(["sbp", "tn", "wave"])
    )
    release_managers: list[str] = sqlmodel.Field(
        default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON), **example(["wave"])
    )

    # M-M: Committee -> [PublicSigningKey]
    # M-M: PublicSigningKey -> [Committee]
    public_signing_keys: list["PublicSigningKey"] = sqlmodel.Relationship(
        back_populates="committees", link_model=KeyLink
    )

    @property
    def display_name(self) -> str:
        """Get the display name for the committee."""
        name = self.full_name or self.name.title()
        return f"{name} (PPMC)" if self.is_podling else name


def see_also(arg: Any) -> None:
    pass


# Project: Project Committee Release DistributionChannel ReleasePolicy
class Project(sqlmodel.SQLModel, table=True):
    # TODO: Consider using key or label for primary string keys
    # Then we can use simply "name" for full_name, and make it str rather than str | None
    name: str = sqlmodel.Field(unique=True, primary_key=True, **example("example"))
    # TODO: Ideally full_name would be unique for str only, but that's complex
    # We always include "Apache" in the full_name
    full_name: str | None = sqlmodel.Field(default=None, **example("Apache Example"))

    status: ProjectStatus = sqlmodel.Field(default=ProjectStatus.ACTIVE, **example(ProjectStatus.ACTIVE))

    # M-1: Project -> Project
    # 1-M: (Project.child_project is missing, would be Project -> [Project])
    super_project_name: str | None = sqlmodel.Field(default=None, foreign_key="project.name")
    # NOTE: Neither "Project" | None nor "Project | None" works
    super_project: Optional["Project"] = sqlmodel.Relationship()

    description: str | None = sqlmodel.Field(default=None, **example("Example is a simple example project"))
    category: str | None = sqlmodel.Field(default=None, **example("data,storage"))
    programming_languages: str | None = sqlmodel.Field(default=None, **example("c,python"))

    # M-1: Project -> Committee
    # 1-M: Committee -> [Project]
    committee_name: str | None = sqlmodel.Field(default=None, foreign_key="committee.name", **example("example"))
    committee: Committee | None = sqlmodel.Relationship(back_populates="projects")
    see_also(Committee.projects)

    # 1-M: Project -> [Release]
    # M-1: Release -> Project
    # see_also(Release.project)
    releases: list["Release"] = sqlmodel.Relationship(back_populates="project")

    # # 1-M: Project -> [DistributionChannel]
    # # M-1: DistributionChannel -> Project
    # distribution_channels: list["DistributionChannel"] = sqlmodel.Relationship(back_populates="project")

    # 1-1: Project -C-> ReleasePolicy
    # 1-1: ReleasePolicy -> Project
    release_policy_id: int | None = sqlmodel.Field(default=None, foreign_key="releasepolicy.id", ondelete="CASCADE")
    release_policy: Optional["ReleasePolicy"] = sqlmodel.Relationship(
        cascade_delete=True, sa_relationship_kwargs={"cascade": "all, delete-orphan", "single_parent": True}
    )

    created: datetime.datetime = sqlmodel.Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC),
        sa_column=sqlalchemy.Column(UTCDateTime),
        **example(datetime.datetime(2025, 5, 1, 1, 2, 3, tzinfo=datetime.UTC)),
    )
    created_by: str | None = sqlmodel.Field(default=None, **example("user"))

    @property
    def display_name(self) -> str:
        """Get the display name for the Project."""
        base = self.full_name or self.name
        if self.committee and self.committee.is_podling:
            return f"{base} (Incubating)"
        return base

    @property
    def short_display_name(self) -> str:
        """Get the short display name for the Project."""
        return self.display_name.removeprefix("Apache ")

    @property
    def policy_announce_release_default(self) -> str:
        return """\
The Apache [COMMITTEE] project team is pleased to announce the
release of [PROJECT] [VERSION].

This is a stable release available for production use.

Downloads are available from the following URL:

[DOWNLOAD_URL]

On behalf of the Apache [COMMITTEE] project team,

[YOUR_FULL_NAME] ([YOUR_ASF_ID])
"""

    @property
    def policy_start_vote_default(self) -> str:
        return """Hello [COMMITTEE],

I'd like to call a vote on releasing the following artifacts as
Apache [PROJECT] [VERSION]. This vote is being conducted using an
Alpha version of the Apache Trusted Releases (ATR) platform.
Please report any bugs or issues to the ASF Tooling team.

The release candidate page, including downloads, can be found at:

  [REVIEW_URL]

The release artifacts are signed with one or more OpenPGP keys from:

  [KEYS_FILE]

Please review the release candidate and vote accordingly.

[ ] +1 Release this package
[ ] +0 Abstain
[ ] -1 Do not release this package (please provide specific comments)

You can vote on ATR at the URL above, or manually by replying to this email.

This vote will remain open for [DURATION] hours.

[RELEASE_CHECKLIST]
Thanks,
[YOUR_FULL_NAME] ([YOUR_ASF_ID])
"""

    @property
    def policy_default_min_hours(self) -> int:
        return 72

    @property
    def policy_announce_release_template(self) -> str:
        if ((policy := self.release_policy) is None) or (policy.announce_release_template == ""):
            return self.policy_announce_release_default
        return policy.announce_release_template

    @property
    def policy_mailto_addresses(self) -> list[str]:
        if ((policy := self.release_policy) is None) or (not policy.mailto_addresses):
            if self.committee is not None:
                return [f"dev@{self.committee.name}.apache.org", f"private@{self.committee.name}.apache.org"]
            else:
                # TODO: Or raise an error?
                return [f"dev@{self.name}.apache.org", f"private@{self.name}.apache.org"]
        return policy.mailto_addresses

    @property
    def policy_manual_vote(self) -> bool:
        if (policy := self.release_policy) is None:
            return False
        return policy.manual_vote

    @property
    def policy_min_hours(self) -> int:
        if ((policy := self.release_policy) is None) or (policy.min_hours is None):
            # TODO: Not sure what the default should be
            return self.policy_default_min_hours
        return policy.min_hours

    @property
    def policy_pause_for_rm(self) -> bool:
        if (policy := self.release_policy) is None:
            return False
        return policy.pause_for_rm

    @property
    def policy_release_checklist(self) -> str:
        if ((policy := self.release_policy) is None) or (policy.release_checklist == ""):
            return ""
        return policy.release_checklist

    @property
    def policy_start_vote_template(self) -> str:
        if ((policy := self.release_policy) is None) or (policy.start_vote_template == ""):
            return self.policy_start_vote_default
        return policy.start_vote_template

    @property
    def policy_binary_artifact_paths(self) -> list[str]:
        if (policy := self.release_policy) is None:
            return []
        # TODO: The type of policy.binary_artifact_paths is list[str]
        # But the production server has None values
        return policy.binary_artifact_paths or []

    @property
    def policy_source_artifact_paths(self) -> list[str]:
        if (policy := self.release_policy) is None:
            return []
        # TODO: The type of policy.source_artifact_paths is list[str]
        # But the production server has None values
        return policy.source_artifact_paths or []

    @property
    def policy_strict_checking(self) -> bool:
        # This is bool, so it should never be None
        # TODO: Should we make it nullable for defaulting?
        if (policy := self.release_policy) is None:
            return False
        return policy.strict_checking

    @property
    def policy_github_repository_name(self) -> str:
        if (policy := self.release_policy) is None:
            return ""
        return policy.github_repository_name

    @property
    def policy_github_compose_workflow_path(self) -> list[str]:
        if (policy := self.release_policy) is None:
            return []
        return policy.github_compose_workflow_path or []

    @property
    def policy_github_vote_workflow_path(self) -> list[str]:
        if (policy := self.release_policy) is None:
            return []
        return policy.github_vote_workflow_path or []

    @property
    def policy_github_finish_workflow_path(self) -> list[str]:
        if (policy := self.release_policy) is None:
            return []
        return policy.github_finish_workflow_path or []

    @property
    def policy_preserve_download_files(self) -> bool:
        if (policy := self.release_policy) is None:
            return False
        return policy.preserve_download_files


# Release: Project ReleasePolicy Revision CheckResult
class Release(sqlmodel.SQLModel, table=True):
    # model_config = compat.SQLModelConfig(extra="forbid", from_attributes=True)

    # We guarantee that "{project.name}-{version}" is unique
    # Therefore we can use that for the name
    name: str = sqlmodel.Field(default="", primary_key=True, unique=True, **example("example-0.0.1"))
    phase: ReleasePhase = sqlmodel.Field(**example(ReleasePhase.RELEASE_CANDIDATE_DRAFT))
    created: datetime.datetime = sqlmodel.Field(
        sa_column=sqlalchemy.Column(UTCDateTime), **example(datetime.datetime(2025, 5, 1, 1, 2, 3, tzinfo=datetime.UTC))
    )
    released: datetime.datetime | None = sqlmodel.Field(
        default=None,
        sa_column=sqlalchemy.Column(UTCDateTime),
        **example(datetime.datetime(2025, 6, 1, 1, 2, 3, tzinfo=datetime.UTC)),
    )

    # M-1: Release -> Project
    # 1-M: Project -> [Release]
    project_name: str = sqlmodel.Field(foreign_key="project.name", **example("example"))
    project: Project = sqlmodel.Relationship(back_populates="releases")
    see_also(Project.releases)

    package_managers: list[str] = sqlmodel.Field(
        default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON), **example([])
    )
    # TODO: Not all releases have a version
    # We could either make this str | None, or we could require version to be set on packages only
    # For example, Apache Airflow Providers do not have an overall version
    # They have one version per package, i.e. per provider
    version: str = sqlmodel.Field(**example("0.0.1"))
    sboms: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON), **example([]))

    # 1-1: Release -C-> ReleasePolicy
    # 1-1: ReleasePolicy -> Release
    release_policy_id: int | None = sqlmodel.Field(default=None, foreign_key="releasepolicy.id")
    release_policy: Optional["ReleasePolicy"] = sqlmodel.Relationship(
        cascade_delete=True, sa_relationship_kwargs={"cascade": "all, delete-orphan", "single_parent": True}
    )

    # VoteEntry is a Pydantic model, not a SQL model
    votes: list[VoteEntry] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))
    vote_manual: bool = sqlmodel.Field(default=False, **example(False))
    vote_started: datetime.datetime | None = sqlmodel.Field(
        default=None,
        sa_column=sqlalchemy.Column(UTCDateTime),
        **example(datetime.datetime(2025, 5, 5, 1, 2, 3, tzinfo=datetime.UTC)),
    )
    vote_resolved: datetime.datetime | None = sqlmodel.Field(
        default=None,
        sa_column=sqlalchemy.Column(UTCDateTime),
        **example(datetime.datetime(2025, 5, 7, 1, 2, 3, tzinfo=datetime.UTC)),
    )
    podling_thread_id: str | None = sqlmodel.Field(default=None, **example("hmk1lpwnnxn5zsbp8gwh7115h2qm7jrh"))

    # 1-M: Release -C-> [Revision]
    # M-1: Revision -> Release
    revisions: list["Revision"] = sqlmodel.Relationship(
        back_populates="release",
        sa_relationship_kwargs={
            "order_by": "Revision.seq",
            "foreign_keys": "[Revision.release_name]",
            "cascade": "all, delete-orphan",
        },
    )

    # 1-M: Release -C-> [CheckResult]
    # M-1: CheckResult -> Release
    check_results: list["CheckResult"] = sqlmodel.Relationship(
        back_populates="release", sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )

    # 1-M: Release -> [Distribution]
    # M-1: Distribution -> Release
    distributions: list["Distribution"] = sqlmodel.Relationship(
        back_populates="release", sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )

    # The combination of project_name and version must be unique
    __table_args__ = (sqlmodel.UniqueConstraint("project_name", "version", name="unique_project_version"),)

    @property
    def committee(self) -> Committee | None:
        """Get the committee for the release."""
        project = self.project
        # Type checker is sure that it can not be None
        # if project is None:
        #     return None
        return project.committee

    @property
    def short_display_name(self) -> str:
        """Get the short display name for the release."""
        return f"{self.project.short_display_name} {self.version}"

    @property
    def unwrap_revision_number(self) -> str:
        """Get the revision number for the release, or raise an exception."""
        number = self.latest_revision_number
        if number is None:
            raise ValueError("Release has no revisions")
        return number

    # TODO: How do we give an example for this?
    @pydantic.computed_field  # type: ignore[prop-decorator]
    @property
    def latest_revision_number(self) -> str | None:
        """Get the latest revision number for the release."""
        # The session must still be active for this to work
        number = getattr(self, "_latest_revision_number", None)
        if not (isinstance(number, str) or (number is None)):
            raise ValueError("Latest revision number is not a str or None")
        return number

    def model_post_init(self, _context):
        if isinstance(self.created, str):
            self.created = datetime.datetime.fromisoformat(self.created.rstrip("Z"))

        if isinstance(self.phase, str):
            self.phase = ReleasePhase(self.phase)

    # NOTE: This does not work
    # But it we set it with Release.latest_revision_number_query = ..., it might work
    # Not clear that we'd want to do that, though
    # @property
    # def latest_revision_number_query(self) -> expression.ScalarSelect[str]:
    #     return (
    #         sqlmodel.select(validate_instrumented_attribute(Revision.number))
    #         .where(validate_instrumented_attribute(Revision.release_name) == Release.name)
    #         .order_by(validate_instrumented_attribute(Revision.seq).desc())
    #         .limit(1)
    #         .scalar_subquery()
    #     )


# SQL models referencing Committee, Project, or Release


# CheckResult: Release
class CheckResult(sqlmodel.SQLModel, table=True):
    # TODO: We have default=None here with a field typed int, not int | None
    id: int = sqlmodel.Field(default=None, primary_key=True, **example(123))

    # M-1: CheckResult -> Release
    # 1-M: Release -C-> [CheckResult]
    release_name: str = sqlmodel.Field(foreign_key="release.name", ondelete="CASCADE", **example("example-0.0.1"))
    release: Release = sqlmodel.Relationship(back_populates="check_results")

    # We don't call this latest_revision_number, because it might not be the latest
    revision_number: str | None = sqlmodel.Field(default=None, index=True, **example("00005"))
    checker: str = sqlmodel.Field(**example("atr.tasks.checks.license.files"))
    primary_rel_path: str | None = sqlmodel.Field(
        default=None, index=True, **example("apache-example-0.0.1-source.tar.gz")
    )
    member_rel_path: str | None = sqlmodel.Field(default=None, index=True, **example("apache-example-0.0.1/pom.xml"))
    created: datetime.datetime = sqlmodel.Field(
        sa_column=sqlalchemy.Column(UTCDateTime),
        **example(datetime.datetime(2025, 5, 1, 1, 2, 3, tzinfo=datetime.UTC)),
    )
    status: CheckResultStatus = sqlmodel.Field(default=CheckResultStatus.SUCCESS, **example(CheckResultStatus.SUCCESS))
    message: str = sqlmodel.Field(**example("sha512 matches for apache-example-0.0.1/pom.xml"))
    data: Any = sqlmodel.Field(
        sa_column=sqlalchemy.Column(sqlalchemy.JSON), **example({"expected": "...", "found": "..."})
    )


class CheckResultIgnore(sqlmodel.SQLModel, table=True):
    id: int = sqlmodel.Field(default=None, primary_key=True, **example(123))
    asf_uid: str = sqlmodel.Field(**example("user"))
    created: datetime.datetime = sqlmodel.Field(
        sa_column=sqlalchemy.Column(UTCDateTime),
        **example(datetime.datetime(2025, 5, 1, 1, 2, 3, tzinfo=datetime.UTC)),
    )
    committee_name: str = sqlmodel.Field(**example("example"))
    release_glob: str | None = sqlmodel.Field(**example("example-0.0.*"))
    revision_number: str | None = sqlmodel.Field(**example("00001"))
    checker_glob: str | None = sqlmodel.Field(**example("atr.tasks.checks.license.files"))
    primary_rel_path_glob: str | None = sqlmodel.Field(**example("apache-example-0.0.1-*.tar.gz"))
    member_rel_path_glob: str | None = sqlmodel.Field(**example("apache-example-0.0.1/*.xml"))
    status: CheckResultStatusIgnore | None = sqlmodel.Field(
        default=None,
        **example(CheckResultStatusIgnore.FAILURE),
    )
    message_glob: str | None = sqlmodel.Field(**example("sha512 matches for apache-example-0.0.1/*.xml"))

    def model_post_init(self, _context):
        if isinstance(self.created, str):
            self.created = datetime.datetime.fromisoformat(self.created.rstrip("Z"))


# Distribution: Release
class Distribution(sqlmodel.SQLModel, table=True):
    release_name: str = sqlmodel.Field(primary_key=True, index=True, foreign_key="release.name", ondelete="CASCADE")
    release: Release = sqlmodel.Relationship(back_populates="distributions")
    platform: DistributionPlatform = sqlmodel.Field(primary_key=True, index=True)
    owner_namespace: str = sqlmodel.Field(primary_key=True, index=True, default="")
    package: str = sqlmodel.Field(primary_key=True, index=True)
    version: str = sqlmodel.Field(primary_key=True, index=True)
    staging: bool = sqlmodel.Field(default=False)
    upload_date: datetime.datetime | None = sqlmodel.Field(default=None)
    api_url: str
    web_url: str | None = sqlmodel.Field(default=None)
    # The API response can be huge, e.g. from npm
    # So we do not store it in the database
    # api_response: Any = sqlmodel.Field(sa_column=sqlalchemy.Column(sqlalchemy.JSON))

    @property
    def identifier(self) -> str:
        def normal(text: str) -> str:
            return text.replace(" ", "_").lower()

        name = normal(self.platform.value.name)
        package = normal(self.package)
        version = normal(self.version)
        return f"{name}-{package}-{version}"

    @property
    def title(self) -> str:
        return f"{self.platform.value.name} {self.package} {self.version}"


# # DistributionChannel: Project
# class DistributionChannel(sqlmodel.SQLModel, table=True):
#     id: int = sqlmodel.Field(default=None, primary_key=True)
#     name: str = sqlmodel.Field(index=True, unique=True)
#     url: str
#     credentials: str
#     is_test: bool = sqlmodel.Field(default=False)
#     automation_endpoint: str
#
#     project_name: str = sqlmodel.Field(foreign_key="project.name")
#
#     # M-1: DistributionChannel -> Project
#     # 1-M: Project -> [DistributionChannel]
#     project: Project = sqlmodel.Relationship(back_populates="distribution_channels")
#     see_also(Project.distribution_channels)


# PublicSigningKey: Committee
class PublicSigningKey(sqlmodel.SQLModel, table=True):
    # The fingerprint must be stored as lowercase hex
    fingerprint: str = sqlmodel.Field(
        primary_key=True, unique=True, **example("0123456789abcdef0123456789abcdef01234567")
    )
    # The algorithm is an RFC 4880 algorithm ID
    algorithm: int = sqlmodel.Field(**example(1))
    # Key length in bits
    length: int = sqlmodel.Field(**example(4096))
    # Creation date
    created: datetime.datetime = sqlmodel.Field(
        sa_column=sqlalchemy.Column(UTCDateTime), **example(datetime.datetime(2025, 5, 1, 1, 2, 3, tzinfo=datetime.UTC))
    )
    # Latest self signature
    latest_self_signature: datetime.datetime | None = sqlmodel.Field(
        default=None, sa_column=sqlalchemy.Column(UTCDateTime)
    )
    # Expiration date
    expires: datetime.datetime | None = sqlmodel.Field(default=None, sa_column=sqlalchemy.Column(UTCDateTime))
    # The primary UID declared in the key
    primary_declared_uid: str | None = sqlmodel.Field(**example("User <user@example.org>"))
    # The secondary UIDs declared in the key
    secondary_declared_uids: list[str] = sqlmodel.Field(
        default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON), **example(["User <user@example.net>"])
    )
    # The UID used by Apache, if available
    apache_uid: str | None = sqlmodel.Field(**example("user"))
    # The ASCII armored key
    ascii_armored_key: str = sqlmodel.Field(
        **example("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n...\n-----END PGP PUBLIC KEY BLOCK-----\n")
    )

    # M-M: PublicSigningKey -> [Committee]
    # M-M: Committee -> [PublicSigningKey]
    committees: list[Committee] = sqlmodel.Relationship(back_populates="public_signing_keys", link_model=KeyLink)

    def model_post_init(self, _context):
        if isinstance(self.created, str):
            self.created = datetime.datetime.fromisoformat(self.created.rstrip("Z"))

        if isinstance(self.latest_self_signature, str):
            self.latest_self_signature = datetime.datetime.fromisoformat(self.latest_self_signature.rstrip("Z"))

        if isinstance(self.expires, str):
            self.expires = datetime.datetime.fromisoformat(self.expires.rstrip("Z"))


# ReleasePolicy: Project
class ReleasePolicy(sqlmodel.SQLModel, table=True):
    id: int = sqlmodel.Field(default=None, primary_key=True)
    mailto_addresses: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))
    manual_vote: bool = sqlmodel.Field(default=False)
    min_hours: int | None = sqlmodel.Field(default=None)
    release_checklist: str = sqlmodel.Field(default="")
    pause_for_rm: bool = sqlmodel.Field(default=False)
    start_vote_template: str = sqlmodel.Field(default="")
    announce_release_template: str = sqlmodel.Field(default="")
    binary_artifact_paths: list[str] = sqlmodel.Field(
        default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON)
    )
    source_artifact_paths: list[str] = sqlmodel.Field(
        default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON)
    )
    strict_checking: bool = sqlmodel.Field(default=False)
    github_repository_name: str = sqlmodel.Field(default="")
    github_compose_workflow_path: list[str] = sqlmodel.Field(
        default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON, nullable=False)
    )
    github_vote_workflow_path: list[str] = sqlmodel.Field(
        default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON, nullable=False)
    )
    github_finish_workflow_path: list[str] = sqlmodel.Field(
        default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON, nullable=False)
    )
    preserve_download_files: bool = sqlmodel.Field(default=False)

    # 1-1: ReleasePolicy -> Project
    # 1-1: Project -C-> ReleasePolicy
    project: Project = sqlmodel.Relationship(back_populates="release_policy")


# Revision: Release
class Revision(sqlmodel.SQLModel, table=True):
    name: str = sqlmodel.Field(default="", primary_key=True, unique=True, **example("example-0.0.1 00002"))

    # M-1: Revision -> Release
    # 1-M: Release -C-> [Revision]
    release_name: str | None = sqlmodel.Field(default=None, foreign_key="release.name", **example("example-0.0.1"))
    release: Release = sqlmodel.Relationship(
        back_populates="revisions",
        sa_relationship_kwargs={
            "foreign_keys": "[Revision.release_name]",
        },
    )

    seq: int = sqlmodel.Field(default=0, **example(1))
    # This was designed as a property, but it's better for it to be a column
    # That way, we can do dynamic Release.latest_revision_number construction easier
    number: str = sqlmodel.Field(default="", **example("00002"))
    asfuid: str = sqlmodel.Field(**example("user"))
    created: datetime.datetime = sqlmodel.Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC),
        sa_column=sqlalchemy.Column(UTCDateTime),
        **example(datetime.datetime(2025, 5, 1, 1, 2, 3, tzinfo=datetime.UTC)),
    )
    phase: ReleasePhase = sqlmodel.Field(**example(ReleasePhase.RELEASE_CANDIDATE_DRAFT))

    # 1-1: Revision -> Revision
    # 1-1: Revision -> Revision
    parent_name: str | None = sqlmodel.Field(
        default=None, foreign_key="revision.name", **example("example-0.0.1 00001")
    )
    parent: Optional["Revision"] = sqlmodel.Relationship(
        sa_relationship_kwargs=dict(
            remote_side=lambda: Revision.name,
            uselist=False,
            primaryjoin=lambda: Revision.parent_name == Revision.name,
            back_populates="child",
        )
    )

    # 1-1: Revision -> Revision
    # 1-1: Revision -> Revision
    child: Optional["Revision"] = sqlmodel.Relationship(back_populates="parent")

    description: str | None = sqlmodel.Field(default=None, **example("This is a description"))

    def model_post_init(self, _context):
        if isinstance(self.created, str):
            self.created = datetime.datetime.fromisoformat(self.created.rstrip("Z"))

        if isinstance(self.phase, str):
            self.phase = ReleasePhase(self.phase)

    __table_args__ = (
        sqlmodel.UniqueConstraint("release_name", "seq", name="uq_revision_release_seq"),
        sqlmodel.UniqueConstraint("release_name", "number", name="uq_revision_release_number"),
    )


def revision_name(release_name: str, number: str) -> str:
    return f"{release_name} {number}"


@event.listens_for(Revision, "before_insert")
def populate_revision_sequence_and_name(
    mapper: orm.Mapper, connection: sqlalchemy.engine.Connection, revision: Revision
) -> None:
    # We require Revision.release_name to have been set
    if not revision.release_name:
        # Raise an exception
        # Otherwise, Revision.name would be "", Revision.seq 0, and Revision.number ""
        raise RuntimeError("Cannot populate revision sequence and name without release_name")

    # Get the Revision with the maximum existing Revision.seq and the same Revision.release_name
    stmt = (
        sqlmodel.select(Revision.seq, Revision.name)
        .where(Revision.release_name == revision.release_name)
        .order_by(sqlalchemy.desc(validate_instrumented_attribute(Revision.seq)))
        .limit(1)
    )
    parent_row = connection.execute(stmt).fetchone()

    # We cannot happy path this, because we must recalculate the Revision.name afterwards
    if parent_row is None:
        # This is the first Revision for this Revision.release_name
        # Revision.seq is 0, but we use a 1-based system
        revision.seq = 1
        revision.number = str(revision.seq).zfill(5)
    else:
        # We don't have the ORM available in this event listener
        # Therefore we must construct a new Revision object from the database row
        parent_row_seq = parent_row.seq
        parent_row_name = parent_row.name
        # Compute the next sequence number
        revision.seq = parent_row_seq + 1
        revision.number = str(revision.seq).zfill(5)
        # Set the parent_name foreign key. SQLAlchemy will handle the relationship.
        revision.parent_name = parent_row_name
        # Do NOT set revision.parent directly here

    # Recalculate the Revision.name
    # This field has a unique constraint, which eliminates the potential for race conditions
    revision.name = revision_name(revision.release_name, revision.number)


@event.listens_for(Release, "before_insert")
def check_release_name(_mapper: orm.Mapper, _connection: sqlalchemy.Connection, release: Release) -> None:
    if release.name == "":
        # Quiet the type checker
        project_name = getattr(release, "project_name", None)
        version = getattr(release, "version", None)
        if (project_name is None) or (version is None):
            raise ValueError("Cannot generate release name without project_name and version")
        release.name = release_name(project_name, version)


def latest_revision_number_query(release_name: str | None = None) -> expression.ScalarSelect[str]:
    if release_name is None:
        query_release_name = Release.name
    else:
        query_release_name = release_name
    return (
        sqlmodel.select(validate_instrumented_attribute(Revision.number))
        .where(validate_instrumented_attribute(Revision.release_name) == query_release_name)
        .order_by(validate_instrumented_attribute(Revision.seq).desc())
        .limit(1)
        .scalar_subquery()
    )


def release_name(project_name: str, version_name: str) -> str:
    """Return the release name for a given project and version."""
    return f"{project_name}-{version_name}"


def validate_instrumented_attribute(obj: Any) -> orm.InstrumentedAttribute:
    """Check if the given object is an InstrumentedAttribute."""
    if not isinstance(obj, orm.InstrumentedAttribute):
        raise ValueError(f"Object must be an orm.InstrumentedAttribute, got: {type(obj)}")
    return obj


RELEASE_LATEST_REVISION_NUMBER: Final = (
    sqlalchemy.select(validate_instrumented_attribute(Revision.number))
    .where(validate_instrumented_attribute(Revision.release_name) == Release.name)
    .order_by(validate_instrumented_attribute(Revision.seq).desc())
    .limit(1)
    .correlate_except(Revision)
    .scalar_subquery()
)


# https://github.com/fastapi/sqlmodel/issues/240#issuecomment-2074161775
Release._latest_revision_number = orm.column_property(RELEASE_LATEST_REVISION_NUMBER)
