"models.py"

import datetime
from typing import List, Optional
from enum import Enum

from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy import Column, JSON
from pydantic import BaseModel


class UserRole(str, Enum):
    PMC_MEMBER = "pmc_member"
    RELEASE_MANAGER = "release_manager"
    COMMITTER = "committer"
    VISITOR = "visitor"
    ASF_MEMBER = "asf_member"
    SYSADMIN = "sysadmin"


class PMCKeyLink(SQLModel, table=True):
    pmc_id: int = Field(foreign_key="pmc.id", primary_key=True)
    key_user_id: str = Field(foreign_key="publicsigningkey.user_id", primary_key=True)


class PublicSigningKey(SQLModel, table=True):
    user_id: str = Field(primary_key=True)
    public_key: str
    key_type: str
    expiration: datetime.datetime
    pmcs: List["PMC"] = Relationship(back_populates="public_signing_keys", link_model=PMCKeyLink)


class VotePolicy(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    mailto_addresses: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    manual_vote: bool = Field(default=False)
    min_hours: int = Field(default=0)
    release_checklist: str = Field(default="")
    pause_for_rm: bool = Field(default=False)

    # One-to-many: A vote policy can be used by multiple PMCs
    pmcs: List["PMC"] = Relationship(back_populates="vote_policy")
    # One-to-many: A vote policy can be used by multiple product lines
    product_lines: List["ProductLine"] = Relationship(back_populates="vote_policy")
    # One-to-many: A vote policy can be used by multiple releases
    releases: List["Release"] = Relationship(back_populates="vote_policy")


class PMC(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_name: str = Field(unique=True)

    # One-to-many: A PMC can have multiple product lines, each product line belongs to one PMC
    product_lines: List["ProductLine"] = Relationship(back_populates="pmc")

    pmc_members: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    committers: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    release_managers: List[str] = Field(default_factory=list, sa_column=Column(JSON))

    # Many-to-many: A PMC can have multiple signing keys, and a signing key can belong to multiple PMCs
    public_signing_keys: List[PublicSigningKey] = Relationship(back_populates="pmcs", link_model=PMCKeyLink)

    # Many-to-one: A PMC can have one vote policy, a vote policy can be used by multiple entities
    vote_policy_id: Optional[int] = Field(default=None, foreign_key="votepolicy.id")
    vote_policy: Optional[VotePolicy] = Relationship(back_populates="pmcs")

    # One-to-many: A PMC can have multiple releases
    releases: List["Release"] = Relationship(back_populates="pmc")


class ProductLine(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    # Many-to-one: A product line belongs to one PMC, a PMC can have multiple product lines
    pmc_id: Optional[int] = Field(default=None, foreign_key="pmc.id")
    pmc: Optional[PMC] = Relationship(back_populates="product_lines")

    product_name: str
    latest_version: str

    # One-to-many: A product line can have multiple distribution channels, each channel belongs to one product line
    distribution_channels: List["DistributionChannel"] = Relationship(back_populates="product_line")

    # Many-to-one: A product line can have one vote policy, a vote policy can be used by multiple entities
    vote_policy_id: Optional[int] = Field(default=None, foreign_key="votepolicy.id")
    vote_policy: Optional[VotePolicy] = Relationship(back_populates="product_lines")

    # One-to-many: A product line can have multiple releases, each release belongs to one product line
    releases: List["Release"] = Relationship(back_populates="product_line")


class DistributionChannel(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    url: str
    credentials: str
    is_test: bool = Field(default=False)
    automation_endpoint: str

    # Many-to-one: A distribution channel belongs to one product line, a product line can have multiple channels
    product_line_id: Optional[int] = Field(default=None, foreign_key="productline.id")
    product_line: Optional[ProductLine] = Relationship(back_populates="distribution_channels")


class Package(BaseModel):
    file: str
    signature: str
    checksum: str


class VoteEntry(BaseModel):
    result: bool
    summary: str
    binding_votes: int
    community_votes: int
    start: datetime.datetime
    end: datetime.datetime


class Release(SQLModel, table=True):
    storage_key: str = Field(primary_key=True)
    stage: str
    phase: str

    # Many-to-one: A release belongs to one PMC, a PMC can have multiple releases
    pmc_id: Optional[int] = Field(default=None, foreign_key="pmc.id")
    pmc: Optional[PMC] = Relationship(back_populates="releases")

    # Many-to-one: A release belongs to one product line, a product line can have multiple releases
    product_line_id: Optional[int] = Field(default=None, foreign_key="productline.id")
    product_line: Optional[ProductLine] = Relationship(back_populates="releases")

    package_managers: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    version: str
    packages: List[Package] = Field(default_factory=list, sa_column=Column(JSON))
    sboms: List[str] = Field(default_factory=list, sa_column=Column(JSON))

    # Many-to-one: A release can have one vote policy, a vote policy can be used by multiple releases
    vote_policy_id: Optional[int] = Field(default=None, foreign_key="votepolicy.id")
    vote_policy: Optional[VotePolicy] = Relationship(back_populates="releases")

    votes: List[VoteEntry] = Field(default_factory=list, sa_column=Column(JSON))
