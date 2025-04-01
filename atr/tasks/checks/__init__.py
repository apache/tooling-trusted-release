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

import datetime
import pathlib
from functools import wraps
from typing import TYPE_CHECKING, Any, TypeVar

import pydantic
import sqlmodel

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

import atr.config as config
import atr.db as db
import atr.db.models as models


class Check:
    def __init__(
        self, checker: Callable[..., Any], release_name: str, path: str | None = None, afresh: bool = True
    ) -> None:
        self.checker = function_key(checker)
        self.release_name = release_name
        self.path = path
        self.afresh = afresh
        self._constructed = False

    @classmethod
    async def create(
        cls, checker: Callable[..., Any], release_name: str, path: str | None = None, afresh: bool = True
    ) -> Check:
        check = cls(checker, release_name, path, afresh)
        if afresh is True:
            # Clear outer path whether it's specified or not
            await check._clear(path)
        check._constructed = True
        return check

    async def _add(
        self, status: models.CheckResultStatus, message: str, data: Any, path: str | None = None
    ) -> models.CheckResult:
        if self._constructed is False:
            raise RuntimeError("Cannot add check result to a check that has not been constructed")
        if path is not None:
            if self.path is not None:
                raise ValueError("Cannot specify path twice")
            if self.afresh is True:
                # Clear inner path only if it's specified
                await self._clear(path)

        result = models.CheckResult(
            release_name=self.release_name,
            checker=self.checker,
            path=path or self.path,
            created=datetime.datetime.now(),
            status=status,
            message=message,
            data=data,
        )

        # It would be more efficient to keep a session open
        # But, we prefer in this case to maintain a simpler interface
        # If performance is unacceptable, we can revisit this design
        async with db.session() as session:
            session.add(result)
            await session.commit()
        return result

    async def _clear(self, path: str | None = None) -> None:
        async with db.session() as data:
            stmt = sqlmodel.delete(models.CheckResult).where(
                db.validate_instrumented_attribute(models.CheckResult.release_name) == self.release_name,
                db.validate_instrumented_attribute(models.CheckResult.checker) == self.checker,
                db.validate_instrumented_attribute(models.CheckResult.path) == path,
            )
            await data.execute(stmt)
            await data.commit()

    async def exception(self, message: str, data: Any, path: str | None = None) -> models.CheckResult:
        return await self._add(models.CheckResultStatus.EXCEPTION, message, data, path=path)

    async def failure(self, message: str, data: Any, path: str | None = None) -> models.CheckResult:
        return await self._add(models.CheckResultStatus.FAILURE, message, data, path=path)

    async def success(self, message: str, data: Any, path: str | None = None) -> models.CheckResult:
        return await self._add(models.CheckResultStatus.SUCCESS, message, data, path=path)

    async def warning(self, message: str, data: Any, path: str | None = None) -> models.CheckResult:
        return await self._add(models.CheckResultStatus.WARNING, message, data, path=path)


def function_key(func: Callable[..., Any]) -> str:
    return func.__module__ + "." + func.__name__


def rel_path(abs_path: str) -> str:
    """Return the relative path for a given absolute path."""
    conf = config.get()
    phase_dir = pathlib.Path(conf.PHASE_STORAGE_DIR)
    phase_sub_dir = pathlib.Path(abs_path).relative_to(phase_dir)
    # Skip the first component, which is the phase name
    # And the next two components, which are the project name and version name
    return str(pathlib.Path(*phase_sub_dir.parts[3:]))


# def using(cls: type[pydantic.BaseModel]) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
#     """Decorator to specify the parameters for a check."""

#     def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
#         @wraps(func)
#         async def wrapper(data_dict: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
#             model_instance = cls(**data_dict)
#             return await func(model_instance, *args, **kwargs)
#         return wrapper

#     return decorator


T = TypeVar("T", bound=pydantic.BaseModel)
R = TypeVar("R")


def with_model(model_class: type[T]) -> Callable[[Callable[..., Awaitable[R]]], Callable[..., Awaitable[R]]]:
    def decorator(func: Callable[..., Awaitable[R]]) -> Callable[..., Awaitable[R]]:
        @wraps(func)
        async def wrapper(data_dict: dict[str, Any], *args: Any, **kwargs: Any) -> R:
            model_instance = model_class(**data_dict)
            return await func(model_instance, *args, **kwargs)

        return wrapper

    return decorator
