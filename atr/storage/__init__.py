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
from typing import TYPE_CHECKING, Final, TypeVar

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

import atr.db as db
import atr.storage.writers as writers

VALIDATE_AT_RUNTIME: Final[bool] = True

# Access

## Access credentials


class AccessCredentials:
    pass


class AccessCredentialsRead(AccessCredentials): ...


class AccessCredentialsWrite(AccessCredentials): ...


A = TypeVar("A", bound=AccessCredentials)
R = TypeVar("R", bound=AccessCredentialsRead)
W = TypeVar("W", bound=AccessCredentialsWrite)

## Access error


class AccessError(RuntimeError): ...


## Access outcome


# TODO: Use actual outcomes here
class AccessOutcome[A]:
    pass


class AccessOutcomeRead(AccessOutcome[R]):
    def __init__(self, accessor_or_exception: R | Exception):
        self.__accessor_or_exception = accessor_or_exception

    def reader_or_raise(self) -> R:
        match self.__accessor_or_exception:
            case AccessCredentialsRead():
                return self.__accessor_or_exception
            case Exception():
                raise self.__accessor_or_exception
        raise AssertionError("Unreachable")


class AccessOutcomeWrite(AccessOutcome[W]):
    def __init__(self, accessor_or_exception: W | Exception):
        self.__accessor_or_exception = accessor_or_exception

    def writer_or_raise(self) -> W:
        match self.__accessor_or_exception:
            case AccessCredentialsWrite():
                return self.__accessor_or_exception
            case Exception():
                raise self.__accessor_or_exception
        raise AssertionError("Unreachable")


# Read


class ReadAsCommitteeMember(AccessCredentialsRead): ...


class ReadAsCommitteeParticipant(AccessCredentialsRead): ...


class ReadAsFoundationMember(AccessCredentialsRead): ...


class ReadAsFoundationParticipant(AccessCredentialsRead): ...


class Read:
    def __init__(self, data: db.Session, asf_uid: str | None = None):
        self.__data = data
        self.__asf_uid = asf_uid


# Write


class WriteAsFoundationParticipant(AccessCredentialsWrite):
    def __init__(self, data: db.Session):
        self.__data = data
        self.__asf_uid = None
        self.__authenticated = True

    @property
    def authenticated(self) -> bool:
        return self.__authenticated

    @property
    def validate_at_runtime(self) -> bool:
        return VALIDATE_AT_RUNTIME


class WriteAsFoundationMember(WriteAsFoundationParticipant):
    def __init__(self, data: db.Session, asf_uid: str):
        if self.validate_at_runtime:
            if not isinstance(asf_uid, str):
                raise AccessError("ASF UID must be a string")
        self.__data = data
        self.__asf_uid = asf_uid
        self.__authenticated = True
        # TODO: We need a definitive list of ASF UIDs
        self.keys = writers.keys.FoundationMember(
            self,
            self.__data,
            self.__asf_uid,
        )

    @property
    def authenticated(self) -> bool:
        return self.__authenticated

    @property
    def validate_at_runtime(self) -> bool:
        return VALIDATE_AT_RUNTIME


class WriteAsCommitteeParticipant(WriteAsFoundationMember):
    def __init__(self, data: db.Session, asf_uid: str, committee_name: str):
        if self.validate_at_runtime:
            if not isinstance(committee_name, str):
                raise AccessError("Committee name must be a string")
        self.__data = data
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name
        self.__authenticated = True
        self.keys = writers.keys.CommitteeParticipant(
            self,
            self.__data,
            self.__asf_uid,
            self.__committee_name,
        )

    @property
    def authenticated(self) -> bool:
        return self.__authenticated

    @property
    def validate_at_runtime(self) -> bool:
        return VALIDATE_AT_RUNTIME


class WriteAsCommitteeMember(WriteAsCommitteeParticipant):
    def __init__(self, data: db.Session, asf_uid: str, committee_name: str):
        self.__data = data
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name
        self.__authenticated = True
        self.keys = writers.keys.CommitteeMember(
            self,
            self.__data,
            self.__asf_uid,
            committee_name,
        )

    @property
    def authenticated(self) -> bool:
        return self.__authenticated

    @property
    def validate_at_runtime(self) -> bool:
        return VALIDATE_AT_RUNTIME


# class WriteAsFoundationAdmin(WriteAsFoundationMember):
#     def __init__(self, data: db.Session, asf_uid: str):
#         self.__data = data
#         self.__asf_uid = asf_uid
#         self.__authenticated = True
#         self.keys = writers.keys.FoundationAdmin(
#             self,
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
    def __init__(self, data: db.Session, asf_uid: str | None = None):
        self.__data = data
        self.__asf_uid = asf_uid

    def as_committee_member(self, committee_name: str) -> AccessOutcomeWrite[WriteAsCommitteeMember]:
        if self.__asf_uid is None:
            return AccessOutcomeWrite(AccessError("No ASF UID"))
        try:
            wacm = WriteAsCommitteeMember(self.__data, self.__asf_uid, committee_name)
        except Exception as e:
            return AccessOutcomeWrite(e)
        return AccessOutcomeWrite(wacm)

    def as_foundation_member(self) -> AccessOutcomeWrite[WriteAsFoundationMember]:
        if self.__asf_uid is None:
            return AccessOutcomeWrite(AccessError("No ASF UID"))
        try:
            wafm = WriteAsFoundationMember(self.__data, self.__asf_uid)
        except Exception as e:
            return AccessOutcomeWrite(e)
        return AccessOutcomeWrite(wafm)


# Context managers


@contextlib.asynccontextmanager
async def read(asf_uid: str | None = None) -> AsyncGenerator[Read]:
    async with db.session() as data:
        # TODO: Replace data with a DatabaseReader instance
        yield Read(data, asf_uid)


@contextlib.asynccontextmanager
async def read_and_write(asf_uid: str | None = None) -> AsyncGenerator[tuple[Read, Write]]:
    async with db.session() as data:
        # TODO: Replace data with DatabaseReader and DatabaseWriter instances
        yield Read(data, asf_uid), Write(data, asf_uid)


@contextlib.asynccontextmanager
async def write(asf_uid: str | None = None) -> AsyncGenerator[Write]:
    async with db.session() as data:
        # TODO: Replace data with a DatabaseWriter instance
        yield Write(data, asf_uid)
