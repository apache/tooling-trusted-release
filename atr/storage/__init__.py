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

from __future__ import annotations

import contextlib
import json
import time
from typing import TYPE_CHECKING, Final

import asfquart.session

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

import atr.db as db
import atr.log as log
import atr.models.sql as sql
import atr.storage.types as types
import atr.storage.writers as writers
import atr.util as util

VALIDATE_AT_RUNTIME: Final[bool] = True

# Access

## Access credentials


class AccessCredentials:
    pass


class AccessCredentialsRead(AccessCredentials): ...


class AccessCredentialsWrite(AccessCredentials): ...


# A = TypeVar("A", bound=AccessCredentials)
# R = TypeVar("R", bound=AccessCredentialsRead)
# W = TypeVar("W", bound=AccessCredentialsWrite)

## Access error


class AccessError(RuntimeError): ...


# Read


class ReadAsCommitteeMember(AccessCredentialsRead): ...


class ReadAsCommitteeParticipant(AccessCredentialsRead): ...


class ReadAsFoundationCommitter(AccessCredentialsRead): ...


class ReadAsGeneralPublic(AccessCredentialsRead): ...


class Read:
    def __init__(self, data: db.Session, asf_uid: str | None, member_of: set[str], participant_of: set[str]):
        self.__data = data
        self.__asf_uid = asf_uid
        self.__member_of = member_of
        self.__participant_of = participant_of


# Write


class WriteAsGeneralPublic(AccessCredentialsWrite):
    def __init__(self, write: Write, data: db.Session):
        self.__write = write
        self.__data = data
        self.__asf_uid = None
        self.__authenticated = True

    @property
    def authenticated(self) -> bool:
        return self.__authenticated

    @property
    def validate_at_runtime(self) -> bool:
        return VALIDATE_AT_RUNTIME


class WriteAsFoundationCommitter(WriteAsGeneralPublic):
    def __init__(self, write: Write, data: db.Session, asf_uid: str):
        if self.validate_at_runtime:
            if not isinstance(asf_uid, str):
                raise AccessError("ASF UID must be a string")
        self.__write = write
        self.__data = data
        self.__asf_uid = asf_uid
        self.__authenticated = True
        # TODO: We need a definitive list of ASF UIDs
        self.keys = writers.keys.FoundationCommitter(
            self,
            self.__write,
            self.__data,
            self.__asf_uid,
        )

    @property
    def authenticated(self) -> bool:
        return self.__authenticated

    @property
    def validate_at_runtime(self) -> bool:
        return VALIDATE_AT_RUNTIME


class WriteAsCommitteeParticipant(WriteAsFoundationCommitter):
    def __init__(self, write: Write, data: db.Session, asf_uid: str, committee_name: str):
        if self.validate_at_runtime:
            if not isinstance(committee_name, str):
                raise AccessError("Committee name must be a string")
        self.__write = write
        self.__data = data
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name
        self.__authenticated = True
        self.keys = writers.keys.CommitteeParticipant(
            self,
            self.__write,
            self.__data,
            self.__asf_uid,
            self.__committee_name,
        )

    @property
    def authenticated(self) -> bool:
        return self.__authenticated

    @property
    def committee_name(self) -> str:
        return self.__committee_name

    @property
    def validate_at_runtime(self) -> bool:
        return VALIDATE_AT_RUNTIME


class WriteAsCommitteeMember(WriteAsCommitteeParticipant):
    def __init__(self, write: Write, data: db.Session, asf_uid: str, committee_name: str):
        self.__write = write
        self.__data = data
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name
        self.__authenticated = True
        self.keys = writers.keys.CommitteeMember(
            self,
            self.__write,
            self.__data,
            self.__asf_uid,
            committee_name,
        )

    @property
    def authenticated(self) -> bool:
        return self.__authenticated

    @property
    def committee_name(self) -> str:
        return self.__committee_name

    @property
    def validate_at_runtime(self) -> bool:
        return VALIDATE_AT_RUNTIME


# class WriteAsFoundationAdmin(WriteAsFoundationCommitter):
#     def __init__(self, write: Write, data: db.Session, asf_uid: str):
#         self.__write = write
#         self.__data = data
#         self.__asf_uid = asf_uid
#         self.__authenticated = True
#         self.keys = writers.keys.FoundationAdmin(
#             self,
#             self.__write,
#             self.__data,
#             self.__asf_uid,
#         )

#     @property
#     def authenticated(self) -> bool:
#         return self.__authenticated

#     @property
#     def validate_at_runtime(self) -> bool:
#         return VALIDATE_AT_RUNTIME


class Write:
    # Read and Write have authenticator methods which return access outcomes
    # TODO: Still need to send some runtime credentials guarantee to the WriteAs* classes
    def __init__(self, data: db.Session, asf_uid: str | None, member_of: set[str], participant_of: set[str]):
        self.__data = data
        self.__asf_uid = asf_uid
        self.__member_of = member_of
        self.__participant_of = participant_of

    # def as_committee_admin(self, committee_name: str) -> types.Outcome[WriteAsCommitteeMember]:
    #     if self.__asf_uid is None:
    #         return types.OutcomeException(AccessError("No ASF UID"))
    #     try:
    #         wacm = WriteAsCommitteeMember(self, self.__data, self.__asf_uid, committee_name)
    #     except Exception as e:
    #         return types.OutcomeException(e)
    #     return types.OutcomeResult(wacm)

    def as_committee_member(self, committee_name: str) -> WriteAsCommitteeMember:
        return self.as_committee_member_outcome(committee_name).result_or_raise()

    def as_committee_member_outcome(self, committee_name: str) -> types.Outcome[WriteAsCommitteeMember]:
        if self.__asf_uid is None:
            return types.OutcomeException(AccessError("No ASF UID"))
        if committee_name not in self.__member_of:
            return types.OutcomeException(AccessError(f"Not a member of {committee_name}"))
        try:
            wacm = WriteAsCommitteeMember(self, self.__data, self.__asf_uid, committee_name)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(wacm)

    def as_committee_participant(self, committee_name: str) -> WriteAsCommitteeParticipant:
        return self.as_committee_participant_outcome(committee_name).result_or_raise()

    def as_committee_participant_outcome(self, committee_name: str) -> types.Outcome[WriteAsCommitteeParticipant]:
        if self.__asf_uid is None:
            return types.OutcomeException(AccessError("No ASF UID"))
        if committee_name not in self.__participant_of:
            return types.OutcomeException(AccessError(f"Not a participant of {committee_name}"))
        try:
            wacp = WriteAsCommitteeParticipant(self, self.__data, self.__asf_uid, committee_name)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(wacp)

    def as_foundation_committer(self) -> WriteAsFoundationCommitter:
        return self.as_foundation_committer_outcome().result_or_raise()

    def as_foundation_committer_outcome(self) -> types.Outcome[WriteAsFoundationCommitter]:
        if self.__asf_uid is None:
            return types.OutcomeException(AccessError("No ASF UID"))
        try:
            wafm = WriteAsFoundationCommitter(self, self.__data, self.__asf_uid)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(wafm)

    # async def as_key_owner(self) -> types.Outcome[WriteAsKeyOwner]:
    #     ...

    async def as_project_committee_member(self, project_name: str) -> WriteAsCommitteeMember:
        write_as_outcome = await self.as_project_committee_member_outcome(project_name)
        return write_as_outcome.result_or_raise()

    async def as_project_committee_member_outcome(self, project_name: str) -> types.Outcome[WriteAsCommitteeMember]:
        project = await self.__data.project(project_name, _committee=True).demand(
            AccessError(f"Project not found: {project_name}")
        )
        if project.committee is None:
            return types.OutcomeException(AccessError("No committee found for project"))
        if self.__asf_uid is None:
            return types.OutcomeException(AccessError("No ASF UID"))
        if project.committee.name not in self.__member_of:
            return types.OutcomeException(AccessError(f"Not a member of {project.committee.name}"))
        try:
            wacm = WriteAsCommitteeMember(self, self.__data, self.__asf_uid, project.committee.name)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(wacm)

    @property
    def member_of(self) -> set[str]:
        return self.__member_of.copy()

    async def member_of_committees(self) -> list[sql.Committee]:
        committees = list(await self.__data.committee(name_in=list(self.__member_of)).all())
        committees.sort(key=lambda c: c.name)
        return [c for c in committees if (not util.committee_is_standing(c.name))]

    @property
    def participant_of(self) -> set[str]:
        return self.__participant_of.copy()

    async def participant_of_committees(self) -> list[sql.Committee]:
        committees = list(await self.__data.committee(name_in=list(self.__participant_of)).all())
        committees.sort(key=lambda c: c.name)
        return [c for c in committees if (not util.committee_is_standing(c.name))]


# Context managers


class ContextManagers:
    def __init__(self, cache_for_at_most_seconds: int = 600):
        self.__cache_for_at_most_seconds = cache_for_at_most_seconds
        self.__member_of_cache: dict[str, set[str]] = {}
        self.__participant_of_cache: dict[str, set[str]] = {}
        self.__last_refreshed = None

    def __outdated(self) -> bool:
        if self.__last_refreshed is None:
            return True
        now = int(time.time())
        since_last_refresh = now - self.__last_refreshed
        return since_last_refresh > self.__cache_for_at_most_seconds

    async def __member_and_participant(self, data: db.Session, asf_uid: str | None) -> tuple[set[str], set[str]]:
        if asf_uid is not None:
            if not self.__outdated():
                return self.__member_of_cache[asf_uid], self.__participant_of_cache[asf_uid]

        start = time.perf_counter_ns()
        try:
            asfquart_session = await asfquart.session.read()
        except Exception:
            if asf_uid is None:
                raise AccessError("No ASF UID, and not in an ASFQuart session")
            asfquart_session_json = await data.ns_text_get("asfquart_session", asf_uid)
            if asfquart_session_json is None:
                raise AccessError("No cached ASFQuart session")
            asfquart_session = json.loads(asfquart_session_json)

        if asfquart_session is None:
            raise AccessError("No ASFQuart session")
        if asf_uid is None:
            asf_uid = asfquart_session.uid
            if asf_uid is None:
                raise AccessError("No ASF UID, and not set in the ASFQuart session")
        elif asfquart_session.uid != asf_uid:
            raise AccessError("ASF UID mismatch")

        # TODO: Use our own LDAP calls instead of using sqlite as a cache
        await data.ns_text_set("asfquart_session", asf_uid, json.dumps(asfquart_session))
        self.__member_of_cache[asf_uid] = set(asfquart_session.committees)
        self.__participant_of_cache[asf_uid] = set(asfquart_session.projects)
        self.__last_refreshed = int(time.time())

        finish = time.perf_counter_ns()
        log.info(f"ContextManagers.__member_and_participant took {finish - start:,} ns")

        return self.__member_of_cache[asf_uid], self.__participant_of_cache[asf_uid]

    @contextlib.asynccontextmanager
    async def read(self, asf_uid: str | None = None) -> AsyncGenerator[Read]:
        async with db.session() as data:
            # TODO: Replace data with a DatabaseReader instance
            member_of, participant_of = await self.__member_and_participant(data, asf_uid)
            yield Read(data, asf_uid, member_of, participant_of)

    @contextlib.asynccontextmanager
    async def write(self, asf_uid: str | None = None) -> AsyncGenerator[Write]:
        async with db.session() as data:
            # TODO: Replace data with a DatabaseWriter instance
            member_of, participant_of = await self.__member_and_participant(data, asf_uid)
            yield Write(data, asf_uid, member_of, participant_of)


_MANAGERS: Final[ContextManagers] = ContextManagers()

read = _MANAGERS.read
write = _MANAGERS.write
