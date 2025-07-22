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
from collections.abc import Callable, Sequence
from typing import NoReturn, TypeVar

import atr.models.schema as schema
import atr.models.sql as sql

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


class OutcomeException[T, E: Exception = Exception](OutcomeCore[T]):
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

    def exception_type_or_none(self) -> type[E] | None:
        return type(self.__exception)


type Outcome[T, E: Exception = Exception] = OutcomeResult[T] | OutcomeException[T, E]


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

    def append(self, outcome: OutcomeResult[T] | OutcomeException[T, Exception]) -> None:
        self.__outcomes.append(outcome)

    def append_roe(self, roe: T | Exception, name: str | None = None) -> None:
        if isinstance(roe, Exception):
            self.__outcomes.append(OutcomeException[T, Exception](roe, name))
        else:
            self.__outcomes.append(OutcomeResult[T](roe, name))

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

    def extend(self, roes: Sequence[T | Exception]) -> None:
        for roe in roes:
            self.append_roe(roe)

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


# TODO: Could use + and += instead, or in addition
def outcomes_merge[T](*outcomes: Outcomes[T]) -> Outcomes[T]:
    return Outcomes(*[outcome for outcome in outcomes for outcome in outcome.outcomes()])
