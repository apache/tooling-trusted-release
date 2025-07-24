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


class VoteEmail(schema.Strict):
    asf_uid_or_email: str
    from_email: str
    status: VoteStatus
    asf_eid: str
    iso_datetime: str
    vote: Vote
    quotation: str
    updated: bool

    @pydantic.field_validator("status", mode="before")
    @classmethod
    def status_to_enum(cls, v):
        return VoteStatus(v) if isinstance(v, str) else v

    @pydantic.field_validator("vote", mode="before")
    @classmethod
    def vote_to_enum(cls, v):
        return Vote(v) if isinstance(v, str) else v


class VoteDetails(schema.Strict):
    start_unixtime: int | None
    votes: dict[str, VoteEmail]
    summary: dict[str, int]
    passed: bool
    outcome: str
