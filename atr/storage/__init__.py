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
import datetime
import json
import logging
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

import atr.db as db
import atr.log as log
import atr.models.basic as basic
import atr.models.sql as sql
import atr.principal as principal
import atr.storage.outcome as outcome
import atr.storage.readers as readers
import atr.storage.writers as writers
import atr.user as user

# Access

## Access credentials


# Do not rename this interface
# It is named to reserve the atr.storage.audit logger name
def audit(**kwargs: basic.JSON) -> None:
    now = datetime.datetime.now(datetime.UTC).isoformat(timespec="milliseconds")
    now = now.replace("+00:00", "Z")
    action = log.caller_name(depth=2)
    kwargs = {"datetime": now, "action": action, **kwargs}
    msg = json.dumps(kwargs, allow_nan=False)
    # The atr.log logger should give the same name
    # But to be extra sure, we set it manually
    logger = logging.getLogger("atr.storage.audit")
    # TODO: Convert to async
    logger.info(msg)


class AccessAs:
    def append_to_audit_log(self, **kwargs: basic.JSON) -> None:
        audit(**kwargs)


class ReadAs(AccessAs): ...


class WriteAs(AccessAs): ...


# A = TypeVar("A", bound=AccessCredentials)
# R = TypeVar("R", bound=AccessCredentialsRead)
# W = TypeVar("W", bound=AccessCredentialsWrite)

## Access error


class AccessError(RuntimeError): ...


# Read


class ReadAsGeneralPublic(ReadAs):
    def __init__(self, read: Read, data: db.Session) -> None:
        self.checks = readers.checks.GeneralPublic(read, self, data)
        self.releases = readers.releases.GeneralPublic(read, self, data)
        self.tokens = readers.tokens.GeneralPublic(read, self, data)


class ReadAsFoundationCommitter(ReadAsGeneralPublic):
    def __init__(self, read: Read, data: db.Session) -> None:
        # self.checks = readers.checks.FoundationCommitter(read, self, data)
        # self.releases = readers.releases.FoundationCommitter(read, self, data)
        self.tokens = readers.tokens.FoundationCommitter(read, self, data)


class ReadAsCommitteeParticipant(ReadAsFoundationCommitter): ...


class ReadAsCommitteeMember(ReadAsFoundationCommitter): ...


class Read:
    def __init__(self, authorisation: principal.Authorisation, data: db.Session):
        self.authorisation = authorisation
        self.__data = data

    # @property
    # def asf_uid(self) -> str | None:
    #     return self.authorisation.asf_uid

    def as_foundation_committer(self) -> ReadAsFoundationCommitter:
        return self.as_foundation_committer_outcome().result_or_raise()

    def as_foundation_committer_outcome(self) -> outcome.Outcome[ReadAsFoundationCommitter]:
        try:
            rafc = ReadAsFoundationCommitter(self, self.__data)
        except Exception as e:
            return outcome.Error(e)
        return outcome.Result(rafc)

    def as_general_public(self) -> ReadAsGeneralPublic:
        return self.as_general_public_outcome().result_or_raise()

    def as_general_public_outcome(self) -> outcome.Outcome[ReadAsGeneralPublic]:
        try:
            ragp = ReadAsGeneralPublic(self, self.__data)
        except Exception as e:
            return outcome.Error(e)
        return outcome.Result(ragp)


# Write


class WriteAsGeneralPublic(WriteAs):
    def __init__(self, write: Write, data: db.Session):
        self.announce = writers.announce.GeneralPublic(write, self, data)
        self.checks = writers.checks.GeneralPublic(write, self, data)
        self.keys = writers.keys.GeneralPublic(write, self, data)
        self.project = writers.project.GeneralPublic(write, self, data)
        self.release = writers.release.GeneralPublic(write, self, data)
        self.sbom = writers.sbom.GeneralPublic(write, self, data)
        self.ssh = writers.ssh.GeneralPublic(write, self, data)
        self.tokens = writers.tokens.GeneralPublic(write, self, data)
        self.vote = writers.vote.GeneralPublic(write, self, data)


class WriteAsFoundationCommitter(WriteAsGeneralPublic):
    def __init__(self, write: Write, data: db.Session):
        # TODO: We need a definitive list of ASF UIDs
        self.__asf_uid = write.authorisation.asf_uid
        self.announce = writers.announce.FoundationCommitter(write, self, data)
        self.checks = writers.checks.FoundationCommitter(write, self, data)
        self.keys = writers.keys.FoundationCommitter(write, self, data)
        self.project = writers.project.FoundationCommitter(write, self, data)
        self.release = writers.release.FoundationCommitter(write, self, data)
        self.sbom = writers.sbom.FoundationCommitter(write, self, data)
        self.ssh = writers.ssh.FoundationCommitter(write, self, data)
        self.tokens = writers.tokens.FoundationCommitter(write, self, data)
        self.vote = writers.vote.FoundationCommitter(write, self, data)

    @property
    def asf_uid(self) -> str:
        if self.__asf_uid is None:
            raise AccessError("No ASF UID")
        return self.__asf_uid


class WriteAsCommitteeParticipant(WriteAsFoundationCommitter):
    def __init__(self, write: Write, data: db.Session, committee_name: str):
        self.__asf_uid = write.authorisation.asf_uid
        self.__committee_name = committee_name
        self.announce = writers.announce.CommitteeParticipant(write, self, data, committee_name)
        self.checks = writers.checks.CommitteeParticipant(write, self, data, committee_name)
        self.keys = writers.keys.CommitteeParticipant(write, self, data, committee_name)
        self.project = writers.project.CommitteeParticipant(write, self, data, committee_name)
        self.release = writers.release.CommitteeParticipant(write, self, data, committee_name)
        self.sbom = writers.sbom.CommitteeParticipant(write, self, data, committee_name)
        self.ssh = writers.ssh.CommitteeParticipant(write, self, data, committee_name)
        self.tokens = writers.tokens.CommitteeParticipant(write, self, data, committee_name)
        self.vote = writers.vote.CommitteeParticipant(write, self, data, committee_name)

    @property
    def asf_uid(self) -> str:
        if self.__asf_uid is None:
            raise AccessError("No ASF UID")
        return self.__asf_uid

    @property
    def committee_name(self) -> str:
        return self.__committee_name


class WriteAsCommitteeMember(WriteAsCommitteeParticipant):
    def __init__(self, write: Write, data: db.Session, committee_name: str):
        self.__asf_uid = write.authorisation.asf_uid
        self.__committee_name = committee_name
        self.announce = writers.announce.CommitteeMember(write, self, data, committee_name)
        self.checks = writers.checks.CommitteeMember(write, self, data, committee_name)
        self.distributions = writers.distributions.CommitteeMember(write, self, data, committee_name)
        self.keys = writers.keys.CommitteeMember(write, self, data, committee_name)
        self.project = writers.project.CommitteeMember(write, self, data, committee_name)
        self.release = writers.release.CommitteeMember(write, self, data, committee_name)
        self.sbom = writers.sbom.CommitteeMember(write, self, data, committee_name)
        self.ssh = writers.ssh.CommitteeMember(write, self, data, committee_name)
        self.tokens = writers.tokens.CommitteeMember(write, self, data, committee_name)
        self.vote = writers.vote.CommitteeMember(write, self, data, committee_name)

    @property
    def asf_uid(self) -> str:
        if self.__asf_uid is None:
            raise AccessError("No ASF UID")
        return self.__asf_uid

    @property
    def committee_name(self) -> str:
        return self.__committee_name


class WriteAsFoundationAdmin(WriteAsCommitteeMember):
    def __init__(self, write: Write, data: db.Session, committee_name: str):
        self.__asf_uid = write.authorisation.asf_uid
        self.__committee_name = committee_name
        self.keys = writers.keys.FoundationAdmin(write, self, data, committee_name)
        self.release = writers.release.FoundationAdmin(write, self, data, committee_name)

    @property
    def asf_uid(self) -> str:
        if self.__asf_uid is None:
            raise AccessError("No ASF UID")
        return self.__asf_uid

    @property
    def committee_name(self) -> str:
        return self.__committee_name


# TODO: Could name this WriteDispatcher
class Write:
    # Read and Write have authenticator methods which return access outcomes
    # TODO: Still need to send some runtime credentials guarantee to the WriteAs* classes
    def __init__(self, authorisation: principal.Authorisation, data: db.Session):
        self.__authorisation: Final[principal.Authorisation] = authorisation
        self.__data: Final[db.Session] = data

    @property
    def authorisation(self) -> principal.Authorisation:
        return self.__authorisation

    def as_committee_member(self, committee_name: str) -> WriteAsCommitteeMember:
        return self.as_committee_member_outcome(committee_name).result_or_raise()

    def as_committee_member_outcome(self, committee_name: str) -> outcome.Outcome[WriteAsCommitteeMember]:
        if self.__authorisation.asf_uid is None:
            return outcome.Error(AccessError("No ASF UID"))
        if not self.__authorisation.is_member_of(committee_name):
            return outcome.Error(
                AccessError(f"ASF UID {self.__authorisation.asf_uid} is not a member of {committee_name}")
            )
        try:
            wacm = WriteAsCommitteeMember(self, self.__data, committee_name)
        except Exception as e:
            return outcome.Error(e)
        return outcome.Result(wacm)

    def as_committee_participant(self, committee_name: str) -> WriteAsCommitteeParticipant:
        return self.as_committee_participant_outcome(committee_name).result_or_raise()

    def as_committee_participant_outcome(self, committee_name: str) -> outcome.Outcome[WriteAsCommitteeParticipant]:
        if self.__authorisation.asf_uid is None:
            return outcome.Error(AccessError("No ASF UID"))
        if not self.__authorisation.is_participant_of(committee_name):
            return outcome.Error(AccessError(f"Not a participant of {committee_name}"))
        try:
            wacp = WriteAsCommitteeParticipant(self, self.__data, committee_name)
        except Exception as e:
            return outcome.Error(e)
        return outcome.Result(wacp)

    def as_foundation_committer(self) -> WriteAsFoundationCommitter:
        return self.as_foundation_committer_outcome().result_or_raise()

    def as_foundation_committer_outcome(self) -> outcome.Outcome[WriteAsFoundationCommitter]:
        if self.__authorisation.asf_uid is None:
            return outcome.Error(AccessError("No ASF UID"))
        try:
            wafm = WriteAsFoundationCommitter(self, self.__data)
        except Exception as e:
            return outcome.Error(e)
        return outcome.Result(wafm)

    def as_foundation_admin(self, committee_name: str) -> WriteAsFoundationAdmin:
        return self.as_foundation_admin_outcome(committee_name).result_or_raise()

    def as_foundation_admin_outcome(self, committee_name: str) -> outcome.Outcome[WriteAsFoundationAdmin]:
        if self.__authorisation.asf_uid is None:
            return outcome.Error(AccessError("No ASF UID"))
        if not user.is_admin(self.__authorisation.asf_uid):
            return outcome.Error(AccessError("Not an admin"))
        try:
            wafa = WriteAsFoundationAdmin(self, self.__data, committee_name)
        except Exception as e:
            return outcome.Error(e)
        return outcome.Result(wafa)

    # async def as_key_owner(self) -> types.Outcome[WriteAsKeyOwner]:
    #     ...

    async def as_project_committee_member(self, project_name: str) -> WriteAsCommitteeMember:
        write_as_outcome = await self.as_project_committee_member_outcome(project_name)
        return write_as_outcome.result_or_raise()

    async def as_project_committee_member_outcome(self, project_name: str) -> outcome.Outcome[WriteAsCommitteeMember]:
        project = await self.__data.project(project_name, _committee=True).demand(
            AccessError(f"Project not found: {project_name}")
        )
        if project.committee is None:
            return outcome.Error(AccessError("No committee found for project"))
        if self.__authorisation.asf_uid is None:
            return outcome.Error(AccessError("No ASF UID"))
        if not self.__authorisation.is_member_of(project.committee.name):
            return outcome.Error(AccessError(f"Not a member of {project.committee.name}"))
        try:
            wacm = WriteAsCommitteeMember(self, self.__data, project.committee.name)
        except Exception as e:
            return outcome.Error(e)
        return outcome.Result(wacm)

    async def as_project_committee_participant(self, project_name: str) -> WriteAsCommitteeParticipant:
        write_as_outcome = await self.as_project_committee_participant_outcome(project_name)
        return write_as_outcome.result_or_raise()

    async def as_project_committee_participant_outcome(
        self, project_name: str
    ) -> outcome.Outcome[WriteAsCommitteeParticipant]:
        project = await self.__data.project(project_name, _committee=True).demand(
            AccessError(f"Project not found: {project_name}")
        )
        if project.committee is None:
            return outcome.Error(AccessError("No committee found for project"))
        if self.__authorisation.asf_uid is None:
            return outcome.Error(AccessError("No ASF UID"))
        if not self.__authorisation.is_participant_of(project.committee.name):
            return outcome.Error(AccessError(f"Not a participant of {project.committee.name}"))
        try:
            wacp = WriteAsCommitteeParticipant(self, self.__data, project.committee.name)
        except Exception as e:
            return outcome.Error(e)
        return outcome.Result(wacp)

    @property
    def member_of(self) -> frozenset[str]:
        return self.__authorisation.member_of()

    async def member_of_committees(self) -> list[sql.Committee]:
        names = list(self.__authorisation.member_of())
        committees = list(await self.__data.committee(name_in=names).all())
        committees.sort(key=lambda c: c.name)
        # Return even standing committees
        return committees

    @property
    def participant_of(self) -> frozenset[str]:
        return self.__authorisation.participant_of()

    async def participant_of_committees(self) -> list[sql.Committee]:
        names = list(self.__authorisation.participant_of())
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
async def read_as_foundation_committer(
    asf_uid: str | None | ArgumentNoneType = ArgumentNone,
) -> AsyncGenerator[ReadAsFoundationCommitter]:
    async with read(asf_uid) as r:
        yield r.as_foundation_committer()


@contextlib.asynccontextmanager
async def read_as_general_public(
    asf_uid: str | None | ArgumentNoneType = ArgumentNone,
) -> AsyncGenerator[ReadAsGeneralPublic]:
    async with read(asf_uid) as r:
        yield r.as_general_public()


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


@contextlib.asynccontextmanager
async def write_as_committee_member(
    committee_name: str,
    asf_uid: str | None | ArgumentNoneType = ArgumentNone,
) -> AsyncGenerator[WriteAsCommitteeMember]:
    async with write(asf_uid) as w:
        yield w.as_committee_member(committee_name)


@contextlib.asynccontextmanager
async def write_as_project_committee_member(
    project_name: str,
    asf_uid: str | None | ArgumentNoneType = ArgumentNone,
) -> AsyncGenerator[WriteAsCommitteeMember]:
    async with write(asf_uid) as w:
        yield await w.as_project_committee_member(project_name)
