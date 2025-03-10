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

import datetime
from enum import Enum
from typing import Any, Optional

import sqlalchemy
import sqlmodel
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncAttrs


class ATRSQLModel(AsyncAttrs, sqlmodel.SQLModel):
    """The base model to use for ATR entities which allows to access related properties in an async manner."""

    pass


class UserRole(str, Enum):
    PMC_MEMBER = "pmc_member"
    RELEASE_MANAGER = "release_manager"
    COMMITTER = "committer"
    VISITOR = "visitor"
    ASF_MEMBER = "asf_member"
    SYSADMIN = "sysadmin"


class PMCKeyLink(sqlmodel.SQLModel, table=True):
    pmc_id: int = sqlmodel.Field(foreign_key="pmc.id", primary_key=True)
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
    # The PMCs that use this key
    pmcs: list["PMC"] = sqlmodel.Relationship(back_populates="_public_signing_keys", link_model=PMCKeyLink)


class VotePolicy(sqlmodel.SQLModel, table=True):
    id: int | None = sqlmodel.Field(default=None, primary_key=True)
    mailto_addresses: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))
    manual_vote: bool = sqlmodel.Field(default=False)
    min_hours: int = sqlmodel.Field(default=0)
    release_checklist: str = sqlmodel.Field(default="")
    pause_for_rm: bool = sqlmodel.Field(default=False)

    # One-to-many: A vote policy can be used by multiple PMCs
    pmcs: list["PMC"] = sqlmodel.Relationship(back_populates="vote_policy")
    # One-to-many: A vote policy can be used by multiple product lines
    product_lines: list["ProductLine"] = sqlmodel.Relationship(back_populates="vote_policy")
    # One-to-many: A vote policy can be used by multiple releases
    releases: list["Release"] = sqlmodel.Relationship(back_populates="vote_policy")


class PMC(ATRSQLModel, table=True):
    id: int | None = sqlmodel.Field(default=None, primary_key=True)
    project_name: str = sqlmodel.Field(unique=True)
    # True if this is an incubator podling with a PPMC, otherwise False
    is_podling: bool = sqlmodel.Field(default=False)

    # One-to-many: A PMC can have multiple product lines, each product line belongs to one PMC
    product_lines: list["ProductLine"] = sqlmodel.Relationship(back_populates="pmc")

    pmc_members: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))
    committers: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))
    release_managers: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))

    # Many-to-many: A PMC can have multiple signing keys, and a signing key can belong to multiple PMCs
    _public_signing_keys: list[PublicSigningKey] = sqlmodel.Relationship(back_populates="pmcs", link_model=PMCKeyLink)

    @property
    async def public_signing_keys(self) -> list[PublicSigningKey]:
        return await self.awaitable_attrs._public_signing_keys  # type: ignore

    # Many-to-one: A PMC can have one vote policy, a vote policy can be used by multiple entities
    vote_policy_id: int | None = sqlmodel.Field(default=None, foreign_key="votepolicy.id")
    vote_policy: VotePolicy | None = sqlmodel.Relationship(back_populates="pmcs")

    # One-to-many: A PMC can have multiple releases
    releases: list["Release"] = sqlmodel.Relationship(back_populates="pmc")

    @property
    def display_name(self) -> str:
        """Get the display name for the PMC/PPMC."""
        if self.is_podling:
            return f"{self.project_name} (podling)"
        return self.project_name


class ProductLine(sqlmodel.SQLModel, table=True):
    id: int | None = sqlmodel.Field(default=None, primary_key=True)

    # Many-to-one: A product line belongs to one PMC, a PMC can have multiple product lines
    pmc_id: int | None = sqlmodel.Field(default=None, foreign_key="pmc.id")
    pmc: PMC | None = sqlmodel.Relationship(back_populates="product_lines")

    product_name: str
    latest_version: str

    # One-to-many: A product line can have multiple distribution channels, each channel belongs to one product line
    distribution_channels: list["DistributionChannel"] = sqlmodel.Relationship(back_populates="product_line")

    # Many-to-one: A product line can have one vote policy, a vote policy can be used by multiple entities
    vote_policy_id: int | None = sqlmodel.Field(default=None, foreign_key="votepolicy.id")
    vote_policy: VotePolicy | None = sqlmodel.Relationship(back_populates="product_lines")

    # One-to-many: A product line can have multiple releases, each release belongs to one product line
    releases: list["Release"] = sqlmodel.Relationship(back_populates="product_line")


class DistributionChannel(sqlmodel.SQLModel, table=True):
    id: int | None = sqlmodel.Field(default=None, primary_key=True)
    name: str = sqlmodel.Field(index=True, unique=True)
    url: str
    credentials: str
    is_test: bool = sqlmodel.Field(default=False)
    automation_endpoint: str

    # Many-to-one: A distribution channel belongs to one product line, a product line can have multiple channels
    product_line_id: int | None = sqlmodel.Field(default=None, foreign_key="productline.id")
    product_line: ProductLine | None = sqlmodel.Relationship(back_populates="distribution_channels")


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
    release_key: str | None = sqlmodel.Field(default=None, foreign_key="release.storage_key")
    release: Optional["Release"] = sqlmodel.Relationship(back_populates="packages")

    # One-to-many: A package can have multiple tasks
    tasks: list["Task"] = sqlmodel.Relationship(
        back_populates="package", sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class VoteEntry(BaseModel):
    result: bool
    summary: str
    binding_votes: int
    community_votes: int
    start: datetime.datetime
    end: datetime.datetime


class ReleaseStage(str, Enum):
    BUILD = "build"
    CANDIDATE = "candidate"
    CURRENT = "current"
    ARCHIVED = "archived"


class ReleasePhase(str, Enum):
    RELEASE_CANDIDATE = "release_candidate"
    EVALUATE_CLAIMS = "evaluate_claims"
    DISTRIBUTE_TEST = "distribute_test"
    VOTE = "vote"
    PASSES = "passes"
    RELEASE = "release"
    DISTRIBUTE = "distribute"
    ANNOUNCE_RELEASE = "announce_release"
    RELEASED = "released"
    MIGRATION = "migration"
    FAILED = "failed"
    ARCHIVED = "archived"


class TaskStatus(str, Enum):
    """Status of a task in the task queue."""

    QUEUED = "queued"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"


class Task(sqlmodel.SQLModel, table=True):
    """A task in the task queue."""

    id: int | None = sqlmodel.Field(default=None, primary_key=True)
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
    storage_key: str = sqlmodel.Field(primary_key=True)
    stage: ReleaseStage
    phase: ReleasePhase
    created: datetime.datetime

    # Many-to-one: A release belongs to one PMC, a PMC can have multiple releases
    pmc_id: int | None = sqlmodel.Field(default=None, foreign_key="pmc.id")
    pmc: PMC | None = sqlmodel.Relationship(back_populates="releases")

    # Many-to-one: A release belongs to one product line, a product line can have multiple releases
    product_line_id: int | None = sqlmodel.Field(default=None, foreign_key="productline.id")
    product_line: ProductLine | None = sqlmodel.Relationship(back_populates="releases")

    package_managers: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))
    version: str
    # One-to-many: A release can have multiple packages
    packages: list[Package] = sqlmodel.Relationship(back_populates="release")
    sboms: list[str] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))

    # Many-to-one: A release can have one vote policy, a vote policy can be used by multiple releases
    vote_policy_id: int | None = sqlmodel.Field(default=None, foreign_key="votepolicy.id")
    vote_policy: VotePolicy | None = sqlmodel.Relationship(back_populates="releases")

    votes: list[VoteEntry] = sqlmodel.Field(default_factory=list, sa_column=sqlalchemy.Column(sqlalchemy.JSON))
