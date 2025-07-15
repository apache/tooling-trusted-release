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


# TODO: ReleasesPagination?
@dataclasses.dataclass
class Releases(Pagination):
    phase: str | None = None


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


class AsfuidPat(schema.Strict):
    asfuid: str
    pat: str


class Fingerprint(schema.Strict):
    endpoint: Literal["/keys/ssh/add"] = schema.Field(alias="endpoint")
    fingerprint: str


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


Results = Annotated[
    AnnounceResults
    | ChecksListResults
    | ChecksOngoingResults
    | CommitteesResults
    | CommitteesKeysResults
    | CommitteesListResults
    | CommitteesProjectsResults
    | Fingerprint,
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
validate_fingerprint = validator(Fingerprint)
