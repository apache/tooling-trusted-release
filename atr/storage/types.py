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
import enum
import pathlib
from collections.abc import Callable, Sequence
from typing import NoReturn, TypeVar

import atr.models.schema as schema
import atr.models.sql as sql

# Outcome

E = TypeVar("E", bound=Exception)
T = TypeVar("T", bound=object)


class OutcomeResult[T]:
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

    def exception_or_raise(self, exception_class: type[Exception] | None = None) -> NoReturn:
        if exception_class is not None:
            raise exception_class(f"Asked for exception on a result: {self.__result}")
        raise RuntimeError(f"Asked for exception on a result: {self.__result}")

    def exception_type_or_none(self) -> type[Exception] | None:
        return None


class OutcomeException[T, E: Exception = Exception]:
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

    def exception_or_none(self) -> E | None:
        return self.__exception

    def exception_or_raise(self, exception_class: type[E] | None = None) -> NoReturn:
        if exception_class is not None:
            raise exception_class(str(self.__exception)) from self.__exception
        raise self.__exception

    def exception_type_or_none(self) -> type[E] | None:
        return type(self.__exception)


type Outcome[T, E: Exception = Exception] = OutcomeResult[T] | OutcomeException[T, E]


class Outcomes[T, E: Exception = Exception]:
    __outcomes: list[Outcome[T, E]]

    def __init__(self, *outcomes: Outcome[T, E]):
        self.__outcomes = list(outcomes)

    def __str__(self) -> str:
        return f"Outcomes({self.__outcomes})"

    @property
    def any_exception(self) -> bool:
        return any((not outcome.ok) for outcome in self.__outcomes)

    @property
    def any_result(self) -> bool:
        return any(outcome.ok for outcome in self.__outcomes)

    @property
    def all_exceptions(self) -> bool:
        return all((not outcome.ok) for outcome in self.__outcomes)

    @property
    def all_results(self) -> bool:
        return all(outcome.ok for outcome in self.__outcomes)

    def append(self, outcome: Outcome[T, E]) -> None:
        self.__outcomes.append(outcome)

    def append_exception(self, exception: E, name: str | None = None) -> None:
        self.__outcomes.append(OutcomeException[T, E](exception, name))

    def append_result(self, result: T, name: str | None = None) -> None:
        self.__outcomes.append(OutcomeResult[T](result, name))

    def append_roe(self, exception_type: type[E], roe: T | E, name: str | None = None) -> None:
        if isinstance(roe, exception_type):
            self.__outcomes.append(OutcomeException[T, E](roe, name))
        elif isinstance(roe, Exception):
            self.__outcomes.append(OutcomeException[T, E](exception_type(str(roe)), name))
        else:
            self.__outcomes.append(OutcomeResult[T](roe, name))

    @property
    def exception_count(self) -> int:
        return sum(1 for outcome in self.__outcomes if isinstance(outcome, OutcomeException))

    def exceptions(self) -> list[E]:
        exceptions_list = []
        for outcome in self.__outcomes:
            if isinstance(outcome, OutcomeException):
                exception_or_none = outcome.exception_or_none()
                if exception_or_none is not None:
                    exceptions_list.append(exception_or_none)
        return exceptions_list

    def exceptions_print(self) -> None:
        for exception in self.exceptions():
            # traceback.print_exception(exception)
            print(exception.__class__.__name__ + ":", exception)

    def extend_exceptions(self, exceptions: Sequence[E]) -> None:
        for exception in exceptions:
            self.append_exception(exception)

    def extend_results(self, results: Sequence[T]) -> None:
        for result in results:
            self.append_result(result)

    def extend_roes(self, exception_type: type[E], roes: Sequence[T | E]) -> None:
        # The name "roe" is short for "result or exception"
        # It looks opaque and jargonistic, but it has an advantage when forming plurals
        # The long form plural is "result or exceptions", which is ambiguous
        # I.e. we mean Seq[Result | Exception], but it also looks like Result | Seq[Exception]
        # The short form, however, encapsulates it so that ROE = Result | Exception
        # Then clearly the short form plural, "roes", means Seq[ROE]
        for roe in roes:
            self.append_roe(exception_type, roe)

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

    def outcomes(self) -> list[Outcome[T, E]]:
        return self.__outcomes

    def result_predicate_count(self, predicate: Callable[[T], bool]) -> int:
        return sum(
            1
            for outcome in self.__outcomes
            if isinstance(outcome, OutcomeResult) and predicate(outcome.result_or_raise())
        )

    def update_roes(self, exception_type: type[E], f: Callable[[T], T]) -> None:
        for i, outcome in enumerate(self.__outcomes):
            if isinstance(outcome, OutcomeResult):
                try:
                    result = f(outcome.result_or_raise())
                except exception_type as e:
                    self.__outcomes[i] = OutcomeException[T, E](e, outcome.name)
                else:
                    self.__outcomes[i] = OutcomeResult[T](result, outcome.name)


@dataclasses.dataclass
class CheckResults:
    primary_results_list: list[sql.CheckResult]
    member_results_list: dict[str, list[sql.CheckResult]]
    ignored_checks: list[sql.CheckResult]


class KeyStatus(enum.Flag):
    PARSED = 0
    INSERTED = enum.auto()
    LINKED = enum.auto()
    INSERTED_AND_LINKED = INSERTED | LINKED


class Key(schema.Strict):
    status: KeyStatus
    key_model: sql.PublicSigningKey


@dataclasses.dataclass
class LinkedCommittee:
    name: str
    autogenerated_keys_file: Outcome[str]


class PathInfo(schema.Strict):
    artifacts: set[pathlib.Path] = schema.factory(set)
    errors: dict[pathlib.Path, list[sql.CheckResult]] = schema.factory(dict)
    metadata: set[pathlib.Path] = schema.factory(set)
    successes: dict[pathlib.Path, list[sql.CheckResult]] = schema.factory(dict)
    warnings: dict[pathlib.Path, list[sql.CheckResult]] = schema.factory(dict)


class PublicKeyError(Exception):
    def __init__(self, key: Key, original_error: Exception):
        self.__key = key
        self.__original_error = original_error

    def __str__(self) -> str:
        return f"PublicKeyError: {self.__original_error}"

    @property
    def key(self) -> Key:
        return self.__key

    @property
    def original_error(self) -> Exception:
        return self.__original_error
