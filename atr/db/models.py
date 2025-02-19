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

"""models.py"""

import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel
from sqlalchemy import JSON, CheckConstraint, Column, Index
from sqlmodel import Field, Relationship, SQLModel


class UserRole(str, Enum):
    PMC_MEMBER = "pmc_member"
    RELEASE_MANAGER = "release_manager"
    COMMITTER = "committer"
    VISITOR = "visitor"
    ASF_MEMBER = "asf_member"
    SYSADMIN = "sysadmin"


class PMCKeyLink(SQLModel, table=True):
    pmc_id: int = Field(foreign_key="pmc.id", primary_key=True)
    key_fingerprint: str = Field(foreign_key="publicsigningkey.fingerprint", primary_key=True)


class PublicSigningKey(SQLModel, table=True):
    # The fingerprint must be stored as lowercase hex
    fingerprint: str = Field(primary_key=True, unique=True)
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
    pmcs: list["PMC"] = Relationship(back_populates="public_signing_keys", link_model=PMCKeyLink)


class VotePolicy(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    mailto_addresses: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    manual_vote: bool = Field(default=False)
    min_hours: int = Field(default=0)
    release_checklist: str = Field(default="")
    pause_for_rm: bool = Field(default=False)

    # One-to-many: A vote policy can be used by multiple PMCs
    pmcs: list["PMC"] = Relationship(back_populates="vote_policy")
    # One-to-many: A vote policy can be used by multiple product lines
    product_lines: list["ProductLine"] = Relationship(back_populates="vote_policy")
    # One-to-many: A vote policy can be used by multiple releases
    releases: list["Release"] = Relationship(back_populates="vote_policy")


class PMC(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    project_name: str = Field(unique=True)

    # One-to-many: A PMC can have multiple product lines, each product line belongs to one PMC
    product_lines: list["ProductLine"] = Relationship(back_populates="pmc")

    pmc_members: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    committers: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    release_managers: list[str] = Field(default_factory=list, sa_column=Column(JSON))

    # Many-to-many: A PMC can have multiple signing keys, and a signing key can belong to multiple PMCs
    public_signing_keys: list[PublicSigningKey] = Relationship(back_populates="pmcs", link_model=PMCKeyLink)

    # Many-to-one: A PMC can have one vote policy, a vote policy can be used by multiple entities
    vote_policy_id: int | None = Field(default=None, foreign_key="votepolicy.id")
    vote_policy: VotePolicy | None = Relationship(back_populates="pmcs")

    # One-to-many: A PMC can have multiple releases
    releases: list["Release"] = Relationship(back_populates="pmc")


class ProductLine(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)

    # Many-to-one: A product line belongs to one PMC, a PMC can have multiple product lines
    pmc_id: int | None = Field(default=None, foreign_key="pmc.id")
    pmc: PMC | None = Relationship(back_populates="product_lines")

    product_name: str
    latest_version: str

    # One-to-many: A product line can have multiple distribution channels, each channel belongs to one product line
    distribution_channels: list["DistributionChannel"] = Relationship(back_populates="product_line")

    # Many-to-one: A product line can have one vote policy, a vote policy can be used by multiple entities
    vote_policy_id: int | None = Field(default=None, foreign_key="votepolicy.id")
    vote_policy: VotePolicy | None = Relationship(back_populates="product_lines")

    # One-to-many: A product line can have multiple releases, each release belongs to one product line
    releases: list["Release"] = Relationship(back_populates="product_line")


class DistributionChannel(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    url: str
    credentials: str
    is_test: bool = Field(default=False)
    automation_endpoint: str

    # Many-to-one: A distribution channel belongs to one product line, a product line can have multiple channels
    product_line_id: int | None = Field(default=None, foreign_key="productline.id")
    product_line: ProductLine | None = Relationship(back_populates="distribution_channels")


class Package(SQLModel, table=True):
    # The SHA3-256 hash of the file, used as filename in storage
    # TODO: We should discuss making this unique
    artifact_sha3: str = Field(primary_key=True)
    # Original filename from uploader
    filename: str
    # SHA-512 hash of the file
    sha512: str
    # The signature file
    signature_sha3: str
    # Uploaded timestamp
    uploaded: datetime.datetime
    # The size of the file in bytes
    bytes_size: int

    # Many-to-one: A package belongs to one release
    release_key: str | None = Field(default=None, foreign_key="release.storage_key")
    release: Optional["Release"] = Relationship(back_populates="packages")


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


class Task(SQLModel, table=True):
    """A task in the task queue."""

    id: int | None = Field(default=None, primary_key=True)
    task_type: str
    task_args: str = Field(sa_column=Column(JSON))
    status: TaskStatus = Field(default=TaskStatus.QUEUED, index=True)
    added: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC), index=True)
    started: datetime.datetime | None = None
    completed: datetime.datetime | None = None
    pid: int | None = None
    error: str | None = None

    # Create an index on status and added for efficient task claiming
    __table_args__ = (
        Index("ix_task_status_added", "status", "added"),
        # Ensure valid status transitions:
        # - QUEUED can transition to ACTIVE
        # - ACTIVE can transition to COMPLETED or FAILED
        # - COMPLETED and FAILED are terminal states
        CheckConstraint(
            """
            (
                -- Initial state is always valid
                status = 'QUEUED'
                -- QUEUED -> ACTIVE requires setting started time and pid
                OR (status = 'ACTIVE' AND started IS NOT NULL AND pid IS NOT NULL)
                -- ACTIVE -> COMPLETED requires setting completed time
                OR (status = 'COMPLETED' AND completed IS NOT NULL)
                -- ACTIVE -> FAILED requires setting completed time and error
                OR (status = 'FAILED' AND completed IS NOT NULL AND error IS NOT NULL)
            )
            """,
            name="valid_task_status_transitions",
        ),
    )


class Release(SQLModel, table=True):
    storage_key: str = Field(primary_key=True)
    stage: ReleaseStage
    phase: ReleasePhase
    created: datetime.datetime

    # Many-to-one: A release belongs to one PMC, a PMC can have multiple releases
    pmc_id: int | None = Field(default=None, foreign_key="pmc.id")
    pmc: PMC | None = Relationship(back_populates="releases")

    # Many-to-one: A release belongs to one product line, a product line can have multiple releases
    product_line_id: int | None = Field(default=None, foreign_key="productline.id")
    product_line: ProductLine | None = Relationship(back_populates="releases")

    package_managers: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    version: str
    # One-to-many: A release can have multiple packages
    packages: list[Package] = Relationship(back_populates="release")
    sboms: list[str] = Field(default_factory=list, sa_column=Column(JSON))

    # Many-to-one: A release can have one vote policy, a vote policy can be used by multiple releases
    vote_policy_id: int | None = Field(default=None, foreign_key="votepolicy.id")
    vote_policy: VotePolicy | None = Relationship(back_populates="releases")

    votes: list[VoteEntry] = Field(default_factory=list, sa_column=Column(JSON))
