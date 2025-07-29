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

import enum
from typing import Any, Literal

import pydantic

from . import schema


class Vote(enum.Enum):
    YES = "Yes"
    NO = "No"
    ABSTAIN = "-"
    UNKNOWN = "?"


class VoteStatus(enum.Enum):
    BINDING = "Binding"
    COMMITTER = "Committer"
    CONTRIBUTOR = "Contributor"
    UNKNOWN = "Unknown"


def example(value: Any) -> dict[Literal["json_schema_extra"], dict[str, Any]]:
    return {"json_schema_extra": {"example": value}}


class VoteEmail(schema.Strict):
    asf_uid_or_email: str = schema.Field(..., **example("user"))
    from_email: str = schema.Field(..., **example("user@example.org"))
    status: VoteStatus = schema.Field(..., **example(VoteStatus.BINDING))
    asf_eid: str = schema.Field(..., **example("102ed8a-503db792-79bc789-b8ca87ce@apache.org"))
    iso_datetime: str = schema.Field(..., **example("2025-05-01T12:00:00Z"))
    vote: Vote = schema.Field(..., **example(Vote.YES))
    quotation: str = schema.Field(..., **example("+1 (Binding)"))
    updated: bool = schema.Field(..., **example(True))

    @pydantic.field_validator("status", mode="before")
    @classmethod
    def status_to_enum(cls, v):
        return VoteStatus(v) if isinstance(v, str) else v

    @pydantic.field_validator("vote", mode="before")
    @classmethod
    def vote_to_enum(cls, v):
        return Vote(v) if isinstance(v, str) else v


class VoteDetails(schema.Strict):
    start_unixtime: int | None = schema.Field(..., **example(1714435200))
    votes: dict[str, VoteEmail] = schema.Field(
        ...,
        **example(
            {
                "user": VoteEmail(
                    asf_uid_or_email="user",
                    from_email="user@example.org",
                    status=VoteStatus.BINDING,
                    asf_eid="102ed8a-503db792-79bc789-b8ca87ce@apache.org",
                    iso_datetime="2025-05-01T12:00:00Z",
                    vote=Vote.YES,
                    quotation="+1 (Binding)",
                    updated=True,
                )
            }
        ),
    )
    summary: dict[str, int] = schema.Field(..., **example({"user": 1}))
    passed: bool = schema.Field(..., **example(True))
    outcome: str = schema.Field(..., **example("The vote passed."))
