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

from collections.abc import Callable, Sequence
from typing import NoReturn, TypeVar

R = TypeVar("R", bound=object)
E = TypeVar("E", bound=Exception)


class Result[R]:
    __match_args__ = ("_result",)
    __result: R

    def __init__(self, result: R, name: str | None = None):
        self.__result = result
        self.__name = name

    @property
    def name(self) -> str | None:
        return self.__name

    @property
    def ok(self) -> bool:
        return True

    @property
    def _result(self) -> R:
        # This is only available on Result
        # It is intended for pattern matching only
        return self.__result

    def error_or_none(self) -> Exception | None:
        return None

    def error_or_raise(self, exception_class: type[Exception] | None = None) -> NoReturn:
        if exception_class is not None:
            raise exception_class(f"Asked for error on a result: {self.__result}")
        raise RuntimeError(f"Asked for error on a result: {self.__result}")

    def error_type_or_none(self) -> type[Exception] | None:
        return None

    def result_or_none(self) -> R | None:
        return self.__result

    def result_or_raise(self, exception_class: type[Exception] | None = None) -> R:
        return self.__result


class Error[R, E: Exception = Exception]:
    __match_args__ = ("_error",)
    __error: E

    def __init__(self, error: E, name: str | None = None):
        self.__error = error
        self.__name = name

    @property
    def name(self) -> str | None:
        return self.__name

    @property
    def ok(self) -> bool:
        return False

    @property
    def _error(self) -> E:
        # This is only available on Error
        # It is intended for pattern matching only
        return self.__error

    def error_or_none(self) -> E | None:
        return self.__error

    def error_or_raise(self, exception_class: type[E] | None = None) -> NoReturn:
        if exception_class is not None:
            raise exception_class(str(self.__error)) from self.__error
        raise self.__error

    def error_type_or_none(self) -> type[E] | None:
        return type(self.__error)

    def result_or_none(self) -> R | None:
        return None

    def result_or_raise(self, exception_class: type[Exception] | None = None) -> NoReturn:
        if exception_class is not None:
            raise exception_class(str(self.__error)) from self.__error
        raise self.__error


type Outcome[R, E: Exception = Exception] = Result[R] | Error[R, E]


class List[R, E: Exception = Exception]:
    __outcomes: list[Outcome[R, E]]

    def __init__(self, *outcomes: Outcome[R, E]):
        self.__outcomes = list(outcomes)

    def __str__(self) -> str:
        return f"Outcomes({self.__outcomes})"

    @property
    def any_error(self) -> bool:
        return any((not outcome.ok) for outcome in self.__outcomes)

    @property
    def any_result(self) -> bool:
        return any(outcome.ok for outcome in self.__outcomes)

    @property
    def all_errors(self) -> bool:
        return all((not outcome.ok) for outcome in self.__outcomes)

    @property
    def all_results(self) -> bool:
        return all(outcome.ok for outcome in self.__outcomes)

    def append(self, outcome: Outcome[R, E]) -> None:
        self.__outcomes.append(outcome)

    def append_error(self, error: E, name: str | None = None) -> None:
        self.__outcomes.append(Error[R, E](error, name))

    def append_result(self, result: R, name: str | None = None) -> None:
        self.__outcomes.append(Result[R](result, name))

    def append_roe(self, exception_type: type[E], roe: R | E, name: str | None = None) -> None:
        if isinstance(roe, exception_type):
            self.__outcomes.append(Error[R, E](roe, name))
        elif isinstance(roe, Exception):
            self.__outcomes.append(Error[R, E](exception_type(str(roe)), name))
        else:
            self.__outcomes.append(Result[R](roe, name))

    @property
    def error_count(self) -> int:
        return sum(1 for outcome in self.__outcomes if isinstance(outcome, Error))

    def errors(self) -> list[E]:
        errors_list = []
        for outcome in self.__outcomes:
            if isinstance(outcome, Error):
                error_or_none = outcome.error_or_none()
                if error_or_none is not None:
                    errors_list.append(error_or_none)
        return errors_list

    def errors_print(self) -> None:
        for error in self.errors():
            # traceback.print_exception(error)
            print(error.__class__.__name__ + ":", error)

    def extend_errors(self, errors: Sequence[E]) -> None:
        for error in errors:
            self.append_error(error)

    def extend_results(self, results: Sequence[R]) -> None:
        for result in results:
            self.append_result(result)

    def extend_roes(self, exception_type: type[E], roes: Sequence[R | E]) -> None:
        # The name "roe" is short for "result or error"
        # It looks opaque and jargonistic, but it has an advantage when forming plurals
        # The long form plural is "result or errors", which is ambiguous
        # I.e. we mean Seq[Result | Error], but it also looks like Result | Seq[Error]
        # The short form, however, encapsulates it so that ROE = Result | Error
        # Then clearly the short form plural, "roes", means Seq[ROE]
        for roe in roes:
            self.append_roe(exception_type, roe)

    def named_results(self) -> dict[str, R]:
        named = {}
        for outcome in self.__outcomes:
            if (outcome.name is not None) and outcome.ok:
                named[outcome.name] = outcome.result_or_raise()
        return named

    def names(self) -> list[str | None]:
        return [outcome.name for outcome in self.__outcomes if (outcome.name is not None)]

    # def replace(self, a: R, b: R) -> None:
    #     for i, outcome in enumerate(self.__outcomes):
    #         if isinstance(outcome, Result):
    #             if outcome.result_or_raise() == a:
    #                 self.__outcomes[i] = Result(b, outcome.name)

    def results_or_raise(self, exception_type: type[Exception] | None = None) -> list[R]:
        return [outcome.result_or_raise(exception_type) for outcome in self.__outcomes]

    def results(self) -> list[R]:
        return [outcome.result_or_raise() for outcome in self.__outcomes if outcome.ok]

    @property
    def result_count(self) -> int:
        return sum(1 for outcome in self.__outcomes if outcome.ok)

    def outcomes(self) -> list[Outcome[R, E]]:
        return self.__outcomes

    def result_predicate_count(self, predicate: Callable[[R], bool]) -> int:
        return sum(
            1 for outcome in self.__outcomes if isinstance(outcome, Result) and predicate(outcome.result_or_raise())
        )

    def update_roes(self, exception_type: type[E], f: Callable[[R], R]) -> None:
        for i, outcome in enumerate(self.__outcomes):
            if isinstance(outcome, Result):
                try:
                    result = f(outcome.result_or_raise())
                except exception_type as e:
                    self.__outcomes[i] = Error[R, E](e, outcome.name)
                else:
                    self.__outcomes[i] = Result[R](result, outcome.name)
