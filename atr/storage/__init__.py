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
import logging
import time
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

import atr.db as db
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

    def as_committee_member(self, committee_name: str) -> types.Outcome[WriteAsCommitteeMember]:
        if self.__asf_uid is None:
            return types.OutcomeException(AccessError("No ASF UID"))
        if committee_name not in self.__member_of:
            return types.OutcomeException(AccessError(f"Not a member of {committee_name}"))
        try:
            wacm = WriteAsCommitteeMember(self, self.__data, self.__asf_uid, committee_name)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(wacm)

    def as_committee_participant(self, committee_name: str) -> types.Outcome[WriteAsCommitteeParticipant]:
        if self.__asf_uid is None:
            return types.OutcomeException(AccessError("No ASF UID"))
        if committee_name not in self.__participant_of:
            return types.OutcomeException(AccessError(f"Not a participant of {committee_name}"))
        try:
            wacp = WriteAsCommitteeParticipant(self, self.__data, self.__asf_uid, committee_name)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(wacp)

    def as_foundation_committer(self) -> types.Outcome[WriteAsFoundationCommitter]:
        if self.__asf_uid is None:
            return types.OutcomeException(AccessError("No ASF UID"))
        try:
            wafm = WriteAsFoundationCommitter(self, self.__data, self.__asf_uid)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(wafm)

    async def as_project_committee_member(self, project_name: str) -> types.Outcome[WriteAsCommitteeMember]:
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
        self.__member_of: dict[str, set[str]] = {}
        self.__participant_of: dict[str, set[str]] = {}
        self.__last_refreshed = None

    def __outdated(self) -> bool:
        if self.__last_refreshed is None:
            return True
        now = int(time.time())
        since_last_refresh = now - self.__last_refreshed
        return since_last_refresh > self.__cache_for_at_most_seconds

    async def __refresh(self, data: db.Session) -> None:
        start = time.perf_counter_ns()
        committees = await data.committee().all()
        for committee in committees:
            for member in committee.committee_members:
                if member not in self.__member_of:
                    self.__member_of[member] = set()
                self.__member_of[member].add(committee.name)
            for participant in committee.committers:
                if participant not in self.__participant_of:
                    self.__participant_of[participant] = set()
                self.__participant_of[participant].add(committee.name)
        self.__last_refreshed = int(time.time())
        finish = time.perf_counter_ns()
        logging.info(f"ContextManagers.__refresh took {finish - start:,} ns")

    async def member_of(self, data: db.Session, asf_uid: str | None = None) -> set[str]:
        start = time.perf_counter_ns()
        if asf_uid is None:
            return set()
        if self.__outdated():
            # This races, but it doesn't matter
            await self.__refresh(data)
        committee_names_set = self.__member_of[asf_uid]
        finish = time.perf_counter_ns()
        logging.info(f"ContextManagers.member_of took {finish - start:,} ns")
        return committee_names_set

    async def participant_of(self, data: db.Session, asf_uid: str | None = None) -> set[str]:
        start = time.perf_counter_ns()
        if asf_uid is None:
            return set()
        if self.__outdated():
            # This races, but it doesn't matter
            await self.__refresh(data)
        committee_names_set = self.__participant_of[asf_uid]
        finish = time.perf_counter_ns()
        logging.info(f"ContextManagers.participant_of took {finish - start:,} ns")
        return committee_names_set

    @contextlib.asynccontextmanager
    async def read(self, asf_uid: str | None = None) -> AsyncGenerator[Read]:
        async with db.session() as data:
            # TODO: Replace data with a DatabaseReader instance
            member_of = await self.member_of(data, asf_uid)
            participant_of = await self.participant_of(data, asf_uid)
            r = Read(data, asf_uid, member_of, participant_of)
            yield r

    @contextlib.asynccontextmanager
    async def read_and_write(self, asf_uid: str | None = None) -> AsyncGenerator[tuple[Read, Write]]:
        async with db.session() as data:
            # TODO: Replace data with DatabaseReader and DatabaseWriter instances
            member_of = await self.member_of(data, asf_uid)
            participant_of = await self.participant_of(data, asf_uid)
            r = Read(data, asf_uid, member_of, participant_of)
            w = Write(data, asf_uid, member_of, participant_of)
            yield r, w

    @contextlib.asynccontextmanager
    async def write(self, asf_uid: str | None = None) -> AsyncGenerator[Write]:
        async with db.session() as data:
            # TODO: Replace data with a DatabaseWriter instance
            member_of = await self.member_of(data, asf_uid)
            participant_of = await self.participant_of(data, asf_uid)
            w = Write(data, asf_uid, member_of, participant_of)
            yield w


_MANAGERS: Final[ContextManagers] = ContextManagers()

read = _MANAGERS.read
read_and_write = _MANAGERS.read_and_write
write = _MANAGERS.write
