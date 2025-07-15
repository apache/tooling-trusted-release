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
from typing import Annotated, Any, Literal

import pydantic

from . import schema


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


class Announce(schema.Strict):
    project: str
    version: str
    revision: str
    email_to: str
    subject: str
    body: str
    path_suffix: str


class AsfuidPat(schema.Strict):
    asfuid: str
    pat: str


class Count(schema.Strict):
    kind: Literal["count"] = schema.Field(alias="kind")
    count: int


class Fingerprint(schema.Strict):
    kind: Literal["fingerprint"] = schema.Field(alias="kind")
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
    Count | Fingerprint,
    schema.Field(discriminator="kind"),
]

ResultsAdapter = pydantic.TypeAdapter(Results)


def validate_count(value: Any) -> Count:
    count = ResultsAdapter.validate_python(value)
    if not isinstance(count, Count):
        raise ResultsTypeError(f"Invalid API response: {value}")
    return count


def validate_fingerprint(value: Any) -> Fingerprint:
    fingerprint = ResultsAdapter.validate_python(value)
    if not isinstance(fingerprint, Fingerprint):
        raise ResultsTypeError(f"Invalid API response: {value}")
    return fingerprint
