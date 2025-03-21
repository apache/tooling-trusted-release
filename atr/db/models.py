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
# from __future__ import annotations

import datetime
import enum
from typing import Any

import pydantic
import sqlalchemy
import sqlalchemy.event as event
import sqlmodel

import atr.db as db


class UserRole(str, enum.Enum):
    COMMITTEE_MEMBER = "committee_member"
    RELEASE_MANAGER = "release_manager"
    COMMITTER = "committer"
    VISITOR = "visitor"
    ASF_MEMBER = "asf_member"
    SYSADMIN = "sysadmin"


class KeyLink(sqlmodel.SQLModel, table=True):
    committee_id: int = sqlmodel.Field(foreign_key="committee.id", primary_key=True)
    key_fingerprint: str = sqlmodel.Field(foreign_key="publicsigningkey.fingerprint", primary_key=True)


class PublicSigningKey(sqlmodel.SQLModel, table=True):
    # The fingerprint must be stored as lowercase hex
    fingerprint: str = sqlmodel.Field(primary_key=True, unique=True)
    # The algorithm is an RFC 4880 algorithm ID
    algorithm: int
    # Key length in bits
    length: int
    # Creation date
    created: datetime.datetime
    # Expiration date
    expires: datetime.datetime | None
    # The UID declared in the key
    declared_uid: str | None
    # The UID used by Apache
    apache_uid: str
    # The ASCII armored key
    ascii_armored_key: str
    # The committees that use this key
    committees: list["Committee"] = sqlmodel.Relationship(back_populates="public_signing_keys", link_model=KeyLink)


class VotePolicy(sqlmodel.SQLModel, table=True):
    id: int = sqlmodel.Field(default=None, primary_key=True)
    mailto_addresses: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))
    manual_vote: bool = sqlmodel.Field(default=False)
    min_hours: int = sqlmodel.Field(default=0)
    release_checklist: str = sqlmodel.Field(default="")
    pause_for_rm: bool = sqlmodel.Field(default=False)

    # One-to-many: A vote policy can be used by multiple committees
    committees: list["Committee"] = sqlmodel.Relationship(back_populates="vote_policy")
    # One-to-many: A vote policy can be used by multiple projects
    projects: list["Project"] = sqlmodel.Relationship(back_populates="vote_policy")
    # One-to-many: A vote policy can be used by multiple releases
    releases: list["Release"] = sqlmodel.Relationship(back_populates="vote_policy")


class Committee(sqlmodel.SQLModel, table=True):
    id: int = sqlmodel.Field(default=None, primary_key=True)
    name: str = sqlmodel.Field(unique=True)
    full_name: str | None = sqlmodel.Field(default=None)
    # True only if this is an incubator podling with a PPMC
    is_podling: bool = sqlmodel.Field(default=False)

    # One-to-many: A committee can have multiple child committees, each child committee belongs to one parent committee
    child_committees: list["Committee"] = sqlmodel.Relationship(
        sa_relationship_kwargs=dict(
            backref=sqlalchemy.orm.backref("parent_committee", remote_side="Committee.id"),
        ),
    )
    parent_committee_id: int | None = sqlmodel.Field(default=None, foreign_key="committee.id")
    # One-to-many: A committee can have multiple projects, each project belongs to one committee
    projects: list["Project"] = sqlmodel.Relationship(back_populates="committee")

    committee_members: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))
    committers: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))
    release_managers: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))

    # Many-to-many: A committee can have multiple signing keys, and a signing key can belong to multiple committees
    public_signing_keys: list[PublicSigningKey] = sqlmodel.Relationship(back_populates="committees", link_model=KeyLink)

    # Many-to-one: A committee can have one vote policy, a vote policy can be used by multiple entities
    vote_policy_id: int | None = sqlmodel.Field(default=None, foreign_key="votepolicy.id")
    vote_policy: VotePolicy | None = sqlmodel.Relationship(back_populates="committees")

    @property
    def display_name(self) -> str:
        """Get the display name for the committee."""
        name = self.name if self.full_name is None else self.full_name
        return f"{name} (PPMC)" if self.is_podling else name


class Project(sqlmodel.SQLModel, table=True):
    id: int = sqlmodel.Field(default=None, primary_key=True)
    name: str = sqlmodel.Field(unique=True)
    # TODO: Ideally full_name would be unique for str only, but that's complex
    full_name: str | None = sqlmodel.Field(default=None)

    # True if this a podling project
    # TODO: We should have this on Committee too, or instead
    is_podling: bool = sqlmodel.Field(default=False)
    is_retired: bool = sqlmodel.Field(default=False)

    description: str | None = sqlmodel.Field(default=None)
    category: str | None = sqlmodel.Field(default=None)
    programming_languages: str | None = sqlmodel.Field(default=None)

    # Many-to-one: A project belongs to one committee, a committee can have multiple projects
    committee_id: int | None = sqlmodel.Field(default=None, foreign_key="committee.id")
    committee: Committee | None = sqlmodel.Relationship(back_populates="projects")

    # One-to-many: A project can have multiple releases, each release belongs to one project
    releases: list["Release"] = sqlmodel.Relationship(back_populates="project")

    # One-to-many: A project can have multiple distribution channels, each channel belongs to one project
    distribution_channels: list["DistributionChannel"] = sqlmodel.Relationship(back_populates="project")

    # Many-to-one: A Project can have one vote policy, a vote policy can be used by multiple entities
    vote_policy_id: int | None = sqlmodel.Field(default=None, foreign_key="votepolicy.id")
    vote_policy: VotePolicy | None = sqlmodel.Relationship(back_populates="projects")

    @property
    def display_name(self) -> str:
        """Get the display name for the Project."""
        name = self.name if self.full_name is None else self.full_name
        return name

    @property
    async def editable_releases(self) -> list["Release"]:
        """Get the editable ongoing releases for the project."""
        # TODO: Improve our interface to use in_ automatically for lists
        editable_phases = [
            ReleasePhase.RELEASE_CANDIDATE,
            ReleasePhase.EVALUATE_CLAIMS,
            ReleasePhase.RELEASE,
        ]
        query = (
            sqlmodel.select(Release)
            .where(
                Release.project_id == self.id,
                db.validate_instrumented_attribute(Release.phase).in_(editable_phases),
            )
            .order_by(db.validate_instrumented_attribute(Release.created).desc())
        )

        results = []
        async with db.session() as data:
            for result in (await data.execute(query)).all():
                release = result[0]
                results.append(release)
        for release in results:
            # Don't need to eager load and lose it when the session closes
            release.project = self
        return results


class DistributionChannel(sqlmodel.SQLModel, table=True):
    id: int = sqlmodel.Field(default=None, primary_key=True)
    name: str = sqlmodel.Field(index=True, unique=True)
    url: str
    credentials: str
    is_test: bool = sqlmodel.Field(default=False)
    automation_endpoint: str

    # Many-to-one: A distribution channel belongs to one project, a project can have multiple channels
    project_id: int = sqlmodel.Field(foreign_key="project.id")
    project: Project = sqlmodel.Relationship(back_populates="distribution_channels")


class Package(sqlmodel.SQLModel, table=True):
    # The SHA3-256 hash of the file, used as filename in storage
    # TODO: We should discuss making this unique
    artifact_sha3: str = sqlmodel.Field(primary_key=True)
    # The type of artifact (source, binary, reproducible binary)
    artifact_type: str
    # Original filename from uploader
    filename: str
    # SHA-512 hash of the file
    sha512: str
    # The signature file
    signature_sha3: str | None = None
    # Uploaded timestamp
    uploaded: datetime.datetime
    # The size of the file in bytes
    bytes_size: int

    # Many-to-one: A package belongs to one release
    release_name: str = sqlmodel.Field(foreign_key="release.name")
    release: "Release" = sqlmodel.Relationship(back_populates="packages")

    # One-to-many: A package can have multiple tasks
    tasks: list["Task"] = sqlmodel.Relationship(
        back_populates="package", sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class VoteEntry(pydantic.BaseModel):
    result: bool
    summary: str
    binding_votes: int
    community_votes: int
    start: datetime.datetime
    end: datetime.datetime


class ReleaseStage(str, enum.Enum):
    BUILD = "build"
    CANDIDATE = "candidate"
    CURRENT = "current"
    ARCHIVED = "archived"


class ReleasePhase(str, enum.Enum):
    # [CANDIDATE]
    # Step 1: The RC is received from external sources
    RELEASE_CANDIDATE = "release_candidate"
    # Step 2: The ATR website evaluates claims about the RC
    EVALUATE_CLAIMS = "evaluate_claims"
    # Step 3: The RC is distributed to project members for testing
    DISTRIBUTE_TEST = "distribute_test"
    # Step 4: The project members are voting on the RC
    VOTE = "vote"
    # Step 5: The project vote on the RC has passed
    PASSES = "passes"

    # [CURRENT]
    # Step 1: The release files are being put in place
    RELEASE = "release"
    # Step 2: The release files are available but not yet announced
    DISTRIBUTE = "distribute"
    # Step 3: The release has been announced but not yet released[?]
    # TODO: Need to check the meaning of this phase
    ANNOUNCE_RELEASE = "announce_release"
    # Step 4: The release has been announced
    RELEASED = "released"

    # [Other]
    # An existing release is being imported from ASF SVN dist
    MIGRATION = "migration"
    # A release candidate has failed at any CANDIDATE stage
    FAILED = "failed"
    # A previously CURRENT release has been archived
    ARCHIVED = "archived"


class TaskStatus(str, enum.Enum):
    """Status of a task in the task queue."""

    QUEUED = "queued"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"


class Task(sqlmodel.SQLModel, table=True):
    """A task in the task queue."""

    id: int = sqlmodel.Field(default=None, primary_key=True)
    status: TaskStatus = sqlmodel.Field(default=TaskStatus.QUEUED, index=True)
    task_type: str
    task_args: Any = sqlmodel.Field(sa_column=sqlalchemy.Column(sqlalchemy.JSON))
    added: datetime.datetime = sqlmodel.Field(default_factory=lambda: datetime.datetime.now(datetime.UTC), index=True)
    started: datetime.datetime | None = None
    pid: int | None = None
    completed: datetime.datetime | None = None
    result: Any | None = sqlmodel.Field(default=None, sa_column=sqlalchemy.Column(sqlalchemy.JSON))
    error: str | None = None

    # Package relationship
    package_sha3: str | None = sqlmodel.Field(default=None, foreign_key="package.artifact_sha3")
    package: Package | None = sqlmodel.Relationship(back_populates="tasks")

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


class Release(sqlmodel.SQLModel, table=True):
    # We guarantee that "{project.name}-{version}" is unique
    # Therefore we can use that for the name
    name: str = sqlmodel.Field(primary_key=True, unique=True)
    stage: ReleaseStage
    phase: ReleasePhase
    created: datetime.datetime

    # Many-to-one: A release belongs to one project, a project can have multiple releases
    project_id: int = sqlmodel.Field(foreign_key="project.id")
    project: Project = sqlmodel.Relationship(back_populates="releases")

    package_managers: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))
    # TODO: Not all releases have a version
    # We could either make this str | None, or we could require version to be set on packages only
    # For example, Apache Airflow Providers do not have an overall version
    # They have one version per package, i.e. per provider
    version: str
    # One-to-many: A release can have multiple packages
    packages: list[Package] = sqlmodel.Relationship(back_populates="release")
    sboms: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))

    # Many-to-one: A release can have one vote policy, a vote policy can be used by multiple releases
    vote_policy_id: int | None = sqlmodel.Field(default=None, foreign_key="votepolicy.id")
    vote_policy: VotePolicy | None = sqlmodel.Relationship(back_populates="releases")

    votes: list[VoteEntry] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))

    # The combination of project_id and version must be unique
    # Technically we want (project.name, version) to be unique
    # But project.name is already unique, so project_id works as a proxy thereof
    __table_args__ = (sqlalchemy.UniqueConstraint("project_id", "version", name="unique_project_version"),)

    @property
    def committee(self) -> Committee | None:
        """Get the committee for the release."""
        project = self.project
        if project is None:
            return None
        return project.committee


@event.listens_for(Release, "before_insert")
def check_release_name(_mapper: sqlalchemy.orm.Mapper, _connection: sqlalchemy.Connection, release: Release) -> None:
    if release.name != f"{release.project.name}-{release.version}":
        raise ValueError(f"Release name must be set to {release.project.name}-{release.version}")


class SSHKey(sqlmodel.SQLModel, table=True):
    fingerprint: str = sqlmodel.Field(primary_key=True)
    key: str
    asf_uid: str
