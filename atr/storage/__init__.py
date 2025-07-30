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
import time
from typing import TYPE_CHECKING, Final

import asfquart.session

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

import atr.committer as committer
import atr.db as db
import atr.log as log
import atr.models.sql as sql
import atr.storage.readers as readers
import atr.storage.types as types
import atr.storage.writers as writers
import atr.user as user

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


class ReadAsGeneralPublic(AccessCredentialsRead):
    def __init__(self, read: Read, data: db.Session, asf_uid: str | None = None):
        self.__read = read
        self.__data = data
        self.__asf_uid = asf_uid
        self.__authenticated = True
        self.checks = readers.checks.GeneralPublic(
            self,
            self.__read,
            self.__data,
            self.__asf_uid,
        )

    @property
    def authenticated(self) -> bool:
        return self.__authenticated

    @property
    def validate_at_runtime(self) -> bool:
        return VALIDATE_AT_RUNTIME


class ReadAsFoundationCommitter(ReadAsGeneralPublic): ...


class ReadAsCommitteeParticipant(ReadAsFoundationCommitter): ...


class ReadAsCommitteeMember(ReadAsFoundationCommitter): ...


class Read:
    def __init__(self, data: db.Session, asf_uid: str | None, member_of: set[str], participant_of: set[str]):
        self.__data = data
        self.__asf_uid = asf_uid
        self.__member_of = member_of
        self.__participant_of = participant_of

    def as_general_public(self) -> ReadAsGeneralPublic:
        return self.as_general_public_outcome().result_or_raise()

    def as_general_public_outcome(self) -> types.Outcome[ReadAsGeneralPublic]:
        try:
            ragp = ReadAsGeneralPublic(self, self.__data, self.__asf_uid)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(ragp)


# Write


class WriteAsGeneralPublic(AccessCredentialsWrite):
    def __init__(self, write: Write, data: db.Session, asf_uid: str | None = None):
        self.__write = write
        self.__data = data
        self.__asf_uid = asf_uid
        self.__authenticated = True
        self.checks = writers.checks.GeneralPublic(
            self,
            self.__write,
            self.__data,
            self.__asf_uid,
        )
        self.keys = writers.keys.GeneralPublic(
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
        self.checks = writers.checks.FoundationCommitter(
            self,
            self.__write,
            self.__data,
            self.__asf_uid,
        )
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
        self.checks = writers.checks.CommitteeParticipant(
            self,
            self.__write,
            self.__data,
            self.__asf_uid,
            self.__committee_name,
        )
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
        self.checks = writers.checks.CommitteeMember(
            self,
            self.__write,
            self.__data,
            self.__asf_uid,
            self.__committee_name,
        )
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


# TODO: Or WriteAsCommitteeAdmin
class WriteAsFoundationAdmin(WriteAsCommitteeMember):
    def __init__(self, write: Write, data: db.Session, asf_uid: str, committee_name: str):
        self.__write = write
        self.__data = data
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name
        self.__authenticated = True
        # self.checks = writers.checks.FoundationAdmin(
        #     self,
        #     self.__write,
        #     self.__data,
        #     self.__asf_uid,
        #     self.__committee_name,
        # )
        self.keys = writers.keys.FoundationAdmin(
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
        if self.__asf_uid in {"sbp", "tn", "wave"}:
            self.__member_of.add("tooling")
            self.__participant_of.add("tooling")
        if committee_name not in self.__member_of:
            return types.OutcomeException(AccessError(f"ASF UID {self.__asf_uid} is not a member of {committee_name}"))
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

    def as_foundation_admin(self, committee_name: str) -> WriteAsFoundationAdmin:
        return self.as_foundation_admin_outcome(committee_name).result_or_raise()

    def as_foundation_admin_outcome(self, committee_name: str) -> types.Outcome[WriteAsFoundationAdmin]:
        if self.__asf_uid is None:
            return types.OutcomeException(AccessError("No ASF UID"))
        if not user.is_admin(self.__asf_uid):
            return types.OutcomeException(AccessError("Not an admin"))
        try:
            wafa = WriteAsFoundationAdmin(self, self.__data, self.__asf_uid, committee_name)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(wafa)

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
        # Return even standing committees
        return committees

    @property
    def participant_of(self) -> set[str]:
        return self.__participant_of.copy()

    async def participant_of_committees(self) -> list[sql.Committee]:
        committees = list(await self.__data.committee(name_in=list(self.__participant_of)).all())
        committees.sort(key=lambda c: c.name)
        # Return even standing committees
        return committees


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
            if asfquart_session:
                if asf_uid is None:
                    asf_uid = asfquart_session.get("uid")
                elif asfquart_session.get("uid") != asf_uid:
                    raise AccessError("ASF UID mismatch")

                if asf_uid:
                    self.__member_of_cache[asf_uid] = set(asfquart_session.get("pmcs", []))
                    self.__participant_of_cache[asf_uid] = set(asfquart_session.get("projects", []))
                    self.__last_refreshed = int(time.time())
                    return self.__member_of_cache[asf_uid], self.__participant_of_cache[asf_uid]
        except Exception:
            pass

        if asf_uid is None:
            raise AccessError("No ASF UID available from session or arguments")

        return await self.__member_and_participant_core(start, asf_uid)

    async def __member_and_participant_core(self, start: int, asf_uid: str) -> tuple[set[str], set[str]]:
        try:
            c = committer.Committer(asf_uid)
            c.verify()
            self.__member_of_cache[asf_uid] = set(c.pmcs)
            self.__participant_of_cache[asf_uid] = set(c.projects)
            self.__last_refreshed = int(time.time())
        except committer.CommitterError as e:
            raise AccessError(f"Failed to verify committer: {e}") from e

        finish = time.perf_counter_ns()
        log.info(f"ContextManagers.__member_and_participant took {finish - start:,} ns")

        # # TODO: An intermittent bug causes Tooling to be missing from the cache
        # # This is a workaround to ensure that Tooling is always included
        # if asf_uid in {"sbp", "tn", "wave"}:
        #     self.__member_of_cache[asf_uid].add("tooling")
        #     self.__participant_of_cache[asf_uid].add("tooling")

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
