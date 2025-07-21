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
from typing import TYPE_CHECKING, Final, NoReturn, TypeVar

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable, Sequence

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


# Outcome

E = TypeVar("E", bound=Exception)
T = TypeVar("T", bound=object)


class OutcomeCore[T]:
    @property
    def ok(self) -> bool:
        raise NotImplementedError("ok is not implemented")

    @property
    def name(self) -> str | None:
        raise NotImplementedError("name is not implemented")

    def result_or_none(self) -> T | None:
        raise NotImplementedError("result_or_none is not implemented")

    def result_or_raise(self, exception_class: type[E] | None = None) -> T:
        raise NotImplementedError("result_or_raise is not implemented")

    def exception_or_none(self) -> Exception | None:
        raise NotImplementedError("exception_or_none is not implemented")

    def exception_type_or_none(self) -> type[Exception] | None:
        raise NotImplementedError("exception_type_or_none is not implemented")


class OutcomeResult[T](OutcomeCore[T]):
    __result: T

    def __init__(self, result: T, name: str | None = None):
        self.__result = result
        self.__name = name

    @property
    def ok(self) -> bool:
        return True

    @property
    def name(self) -> str | None:
        return self.__name

    def result_or_none(self) -> T | None:
        return self.__result

    def result_or_raise(self, exception_class: type[Exception] | None = None) -> T:
        return self.__result

    def exception_or_none(self) -> Exception | None:
        return None

    def exception_type_or_none(self) -> type[Exception] | None:
        return None


class OutcomeException[T, E: Exception](OutcomeCore[T]):
    __exception: E

    def __init__(self, exception: E, name: str | None = None):
        self.__exception = exception
        self.__name = name

    @property
    def ok(self) -> bool:
        return False

    @property
    def name(self) -> str | None:
        return self.__name

    def result_or_none(self) -> T | None:
        return None

    def result_or_raise(self, exception_class: type[Exception] | None = None) -> NoReturn:
        if exception_class is not None:
            raise exception_class(str(self.__exception)) from self.__exception
        raise self.__exception

    def exception_or_none(self) -> Exception | None:
        return self.__exception

    def exception_type_or_none(self) -> type[Exception] | None:
        return type(self.__exception)


class Outcomes[T]:
    __outcomes: list[OutcomeResult[T] | OutcomeException[T, Exception]]

    def __init__(self, *outcomes: OutcomeResult[T] | OutcomeException[T, Exception]):
        self.__outcomes = list(outcomes)

    @property
    def any_ok(self) -> bool:
        return any(outcome.ok for outcome in self.__outcomes)

    @property
    def all_ok(self) -> bool:
        return all(outcome.ok for outcome in self.__outcomes)

    def append(self, result_or_error: T | Exception, name: str | None = None) -> None:
        if isinstance(result_or_error, Exception):
            self.__outcomes.append(OutcomeException(result_or_error, name))
        else:
            self.__outcomes.append(OutcomeResult(result_or_error, name))

    @property
    def exception_count(self) -> int:
        return sum(1 for outcome in self.__outcomes if isinstance(outcome, OutcomeException))

    def exceptions(self) -> list[Exception]:
        exceptions_list = []
        for outcome in self.__outcomes:
            if isinstance(outcome, OutcomeException):
                exception_or_none = outcome.exception_or_none()
                if exception_or_none is not None:
                    exceptions_list.append(exception_or_none)
        return exceptions_list

    def extend(self, result_or_error_list: Sequence[T | Exception]) -> None:
        for result_or_error in result_or_error_list:
            self.append(result_or_error)

    def named_results(self) -> dict[str, T]:
        named = {}
        for outcome in self.__outcomes:
            if (outcome.name is not None) and outcome.ok:
                named[outcome.name] = outcome.result_or_raise()
        return named

    def names(self) -> list[str | None]:
        return [outcome.name for outcome in self.__outcomes if (outcome.name is not None)]

    # def replace(self, a: T, b: T) -> None:
    #     for i, outcome in enumerate(self.__outcomes):
    #         if isinstance(outcome, OutcomeResult):
    #             if outcome.result_or_raise() == a:
    #                 self.__outcomes[i] = OutcomeResult(b, outcome.name)

    def results_or_raise(self, exception_class: type[Exception] | None = None) -> list[T]:
        return [outcome.result_or_raise(exception_class) for outcome in self.__outcomes]

    def results(self) -> list[T]:
        return [outcome.result_or_raise() for outcome in self.__outcomes if outcome.ok]

    @property
    def result_count(self) -> int:
        return sum(1 for outcome in self.__outcomes if outcome.ok)

    def outcomes(self) -> list[OutcomeResult[T] | OutcomeException[T, Exception]]:
        return self.__outcomes

    def result_predicate_count(self, predicate: Callable[[T], bool]) -> int:
        return sum(
            1
            for outcome in self.__outcomes
            if isinstance(outcome, OutcomeResult) and predicate(outcome.result_or_raise())
        )

    def update_results(self, f: Callable[[T], T]) -> None:
        for i, outcome in enumerate(self.__outcomes):
            if isinstance(outcome, OutcomeResult):
                try:
                    result = f(outcome.result_or_raise())
                except Exception as e:
                    self.__outcomes[i] = OutcomeException(e, outcome.name)
                else:
                    self.__outcomes[i] = OutcomeResult(result, outcome.name)


# TODO: Could use + and += instead, or in addition
def outcomes_merge[T](*outcomes: Outcomes[T]) -> Outcomes[T]:
    return Outcomes(*[outcome for outcome in outcomes for outcome in outcome.outcomes()])


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
