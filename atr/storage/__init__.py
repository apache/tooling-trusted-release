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
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

import atr.db as db

# import atr.log as log
import atr.models.sql as sql
import atr.principal as principal
import atr.storage.readers as readers
import atr.storage.types as types
import atr.storage.writers as writers
import atr.user as user

# Access

## Access credentials


def audit(msg: str) -> None:
    msg = msg.replace("\n", " / ")
    # The atr.log logger should give the same name
    # But to be extra sure, we set it manually
    logger = logging.getLogger("atr.storage.audit")
    logger.info(msg)


class AccessCredentials:
    def audit_worthy_event(self, msg: str) -> None:
        audit(msg)


class AccessCredentialsRead(AccessCredentials): ...


class AccessCredentialsWrite(AccessCredentials): ...


# A = TypeVar("A", bound=AccessCredentials)
# R = TypeVar("R", bound=AccessCredentialsRead)
# W = TypeVar("W", bound=AccessCredentialsWrite)

## Access error


class AccessError(RuntimeError): ...


# Read


class ReadAsGeneralPublic(AccessCredentialsRead):
    def __init__(self, read: Read, data: db.Session):
        self.checks = readers.checks.GeneralPublic(self, read, data)
        self.releases = readers.releases.GeneralPublic(self, read, data)


class ReadAsFoundationCommitter(ReadAsGeneralPublic): ...


class ReadAsCommitteeParticipant(ReadAsFoundationCommitter): ...


class ReadAsCommitteeMember(ReadAsFoundationCommitter): ...


class Read:
    def __init__(self, authorisation: principal.Authorisation, data: db.Session):
        self.authorisation = authorisation
        self.__data = data

    def as_general_public(self) -> ReadAsGeneralPublic:
        return self.as_general_public_outcome().result_or_raise()

    def as_general_public_outcome(self) -> types.Outcome[ReadAsGeneralPublic]:
        try:
            ragp = ReadAsGeneralPublic(self, self.__data)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(ragp)


# Write


class WriteAsGeneralPublic(AccessCredentialsWrite):
    def __init__(self, write: Write, data: db.Session):
        self.checks = writers.checks.GeneralPublic(self, write, data)
        self.keys = writers.keys.GeneralPublic(self, write, data)


class WriteAsFoundationCommitter(WriteAsGeneralPublic):
    def __init__(self, write: Write, data: db.Session):
        # TODO: We need a definitive list of ASF UIDs
        self.checks = writers.checks.FoundationCommitter(self, write, data)
        self.keys = writers.keys.FoundationCommitter(self, write, data)


class WriteAsCommitteeParticipant(WriteAsFoundationCommitter):
    def __init__(self, write: Write, data: db.Session, committee_name: str):
        self.__committee_name = committee_name
        self.checks = writers.checks.CommitteeParticipant(self, write, data, committee_name)
        self.keys = writers.keys.CommitteeParticipant(self, write, data, committee_name)

    @property
    def committee_name(self) -> str:
        return self.__committee_name


class WriteAsCommitteeMember(WriteAsCommitteeParticipant):
    def __init__(self, write: Write, data: db.Session, committee_name: str):
        self.__committee_name = committee_name
        self.checks = writers.checks.CommitteeMember(self, write, data, committee_name)
        self.keys = writers.keys.CommitteeMember(self, write, data, committee_name)

    @property
    def committee_name(self) -> str:
        return self.__committee_name


# TODO: Or WriteAsCommitteeAdmin
class WriteAsFoundationAdmin(WriteAsCommitteeMember):
    def __init__(self, write: Write, data: db.Session, committee_name: str):
        self.__committee_name = committee_name
        # self.checks = writers.checks.FoundationAdmin(self, write, data, committee_name)
        self.keys = writers.keys.FoundationAdmin(self, write, data, committee_name)

    @property
    def committee_name(self) -> str:
        return self.__committee_name


class Write:
    # Read and Write have authenticator methods which return access outcomes
    # TODO: Still need to send some runtime credentials guarantee to the WriteAs* classes
    def __init__(self, authorisation: principal.Authorisation, data: db.Session):
        self.__authorisation: Final[principal.Authorisation] = authorisation
        self.__data: Final[db.Session] = data

    @property
    def authorisation(self) -> principal.Authorisation:
        return self.__authorisation

    # def as_committee_admin(self, committee_name: str) -> types.Outcome[WriteAsCommitteeMember]:
    #     if self.__asf_uid is None:
    #         return types.OutcomeException(AccessError("No ASF UID"))
    #     try:
    #         wacm = WriteAsCommitteeMember(self, self.__data, self.__asf_uid, committee_name)
    #     except Exception as e:
    #         return types.OutcomeException(e)
    #     return types.OutcomeResult(wacm)

    async def as_committee_member(self, committee_name: str) -> WriteAsCommitteeMember:
        return (await self.as_committee_member_outcome(committee_name)).result_or_raise()

    async def as_committee_member_outcome(self, committee_name: str) -> types.Outcome[WriteAsCommitteeMember]:
        if self.__authorisation.asf_uid is None:
            return types.OutcomeException(AccessError("No ASF UID"))
        if not (await self.__authorisation.is_member_of(committee_name)):
            return types.OutcomeException(
                AccessError(f"ASF UID {self.__authorisation.asf_uid} is not a member of {committee_name}")
            )
        try:
            wacm = WriteAsCommitteeMember(self, self.__data, committee_name)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(wacm)

    async def as_committee_participant(self, committee_name: str) -> WriteAsCommitteeParticipant:
        return (await self.as_committee_participant_outcome(committee_name)).result_or_raise()

    async def as_committee_participant_outcome(self, committee_name: str) -> types.Outcome[WriteAsCommitteeParticipant]:
        if self.__authorisation.asf_uid is None:
            return types.OutcomeException(AccessError("No ASF UID"))
        if not (await self.__authorisation.is_participant_of(committee_name)):
            return types.OutcomeException(AccessError(f"Not a participant of {committee_name}"))
        try:
            wacp = WriteAsCommitteeParticipant(self, self.__data, committee_name)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(wacp)

    def as_foundation_committer(self) -> WriteAsFoundationCommitter:
        return self.as_foundation_committer_outcome().result_or_raise()

    def as_foundation_committer_outcome(self) -> types.Outcome[WriteAsFoundationCommitter]:
        if self.__authorisation.asf_uid is None:
            return types.OutcomeException(AccessError("No ASF UID"))
        try:
            wafm = WriteAsFoundationCommitter(self, self.__data)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(wafm)

    def as_foundation_admin(self, committee_name: str) -> WriteAsFoundationAdmin:
        return self.as_foundation_admin_outcome(committee_name).result_or_raise()

    def as_foundation_admin_outcome(self, committee_name: str) -> types.Outcome[WriteAsFoundationAdmin]:
        if self.__authorisation.asf_uid is None:
            return types.OutcomeException(AccessError("No ASF UID"))
        if not user.is_admin(self.__authorisation.asf_uid):
            return types.OutcomeException(AccessError("Not an admin"))
        try:
            wafa = WriteAsFoundationAdmin(self, self.__data, committee_name)
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
        if self.__authorisation.asf_uid is None:
            return types.OutcomeException(AccessError("No ASF UID"))
        if not (await self.__authorisation.is_member_of(project.committee.name)):
            return types.OutcomeException(AccessError(f"Not a member of {project.committee.name}"))
        try:
            wacm = WriteAsCommitteeMember(self, self.__data, project.committee.name)
        except Exception as e:
            return types.OutcomeException(e)
        return types.OutcomeResult(wacm)

    async def member_of(self) -> frozenset[str]:
        return await self.__authorisation.member_of()

    async def member_of_committees(self) -> list[sql.Committee]:
        names = list(await self.__authorisation.member_of())
        committees = list(await self.__data.committee(name_in=names).all())
        committees.sort(key=lambda c: c.name)
        # Return even standing committees
        return committees

    async def participant_of(self) -> frozenset[str]:
        return await self.__authorisation.participant_of()

    async def participant_of_committees(self) -> list[sql.Committee]:
        names = list(await self.__authorisation.participant_of())
        committees = list(await self.__data.committee(name_in=names).all())
        committees.sort(key=lambda c: c.name)
        # Return even standing committees
        return committees


# Context managers


class ArgumentNoneType:
    pass


ArgumentNone = ArgumentNoneType()


@contextlib.asynccontextmanager
async def read(asf_uid: str | None | ArgumentNoneType = ArgumentNone) -> AsyncGenerator[Read]:
    if asf_uid is ArgumentNone:
        authorisation = await principal.Authorisation()
    else:
        authorisation = await principal.Authorisation(asf_uid)
    async with db.session() as data:
        # TODO: Replace data with a DatabaseReader instance
        yield Read(authorisation, data)


@contextlib.asynccontextmanager
async def read_and_write(asf_uid: str | None | ArgumentNoneType = ArgumentNone) -> AsyncGenerator[tuple[Read, Write]]:
    if asf_uid is ArgumentNone:
        authorisation = await principal.Authorisation()
    else:
        authorisation = await principal.Authorisation(asf_uid)
    async with db.session() as data:
        # TODO: Replace data with a DatabaseWriter instance
        r = Read(authorisation, data)
        w = Write(authorisation, data)
        yield r, w


@contextlib.asynccontextmanager
async def write(asf_uid: str | None | ArgumentNoneType = ArgumentNone) -> AsyncGenerator[Write]:
    if asf_uid is ArgumentNone:
        authorisation = await principal.Authorisation()
    else:
        authorisation = await principal.Authorisation(asf_uid)
    async with db.session() as data:
        # TODO: Replace data with a DatabaseWriter instance
        yield Write(authorisation, data)
