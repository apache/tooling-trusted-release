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

import dataclasses
import datetime
import pathlib
from functools import wraps
from typing import TYPE_CHECKING, Any

import sqlmodel

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    import pydantic

import atr.db as db
import atr.db.models as models
import atr.util as util


# Pydantic does not like Callable types, so we use a dataclass instead
# It says: "you should define `Callable`, then call `FunctionArguments.model_rebuild()`"
@dataclasses.dataclass
class FunctionArguments:
    recorder: Callable[[], Awaitable[Recorder]]
    release_name: str
    draft_revision: str
    primary_rel_path: str | None
    extra_args: dict[str, Any]


class Recorder:
    checker: str
    release_name: str
    project_name: str
    version_name: str
    primary_rel_path: str | None
    draft_revision: str
    afresh: bool

    def __init__(
        self,
        checker: str | Callable[..., Any],
        release_name: str,
        draft_revision: str,
        primary_rel_path: str | None = None,
        afresh: bool = True,
    ) -> None:
        self.checker = function_key(checker) if callable(checker) else checker
        self.release_name = release_name
        self.draft_revision = draft_revision
        self.primary_rel_path = primary_rel_path
        self.afresh = afresh
        self.constructed = False

        project_name, version_name = models.project_version(release_name)
        self.project_name = project_name
        self.version_name = version_name

    @classmethod
    async def create(
        cls,
        checker: str | Callable[..., Any],
        release_name: str,
        draft_revision: str,
        primary_rel_path: str | None = None,
        afresh: bool = True,
    ) -> Recorder:
        recorder = cls(checker, release_name, draft_revision, primary_rel_path, afresh)
        if afresh is True:
            # Clear outer path whether it's specified or not
            await recorder.clear(primary_rel_path)
        recorder.constructed = True
        return recorder

    async def _add(
        self, status: models.CheckResultStatus, message: str, data: Any, primary_rel_path: str | None = None
    ) -> models.CheckResult:
        if self.constructed is False:
            raise RuntimeError("Cannot add check result to a recorder that has not been constructed")
        if primary_rel_path is not None:
            if self.primary_rel_path is not None:
                raise ValueError("Cannot specify path twice")
            if self.afresh is True:
                # Clear inner path only if it's specified
                await self.clear(primary_rel_path)

        result = models.CheckResult(
            release_name=self.release_name,
            checker=self.checker,
            primary_rel_path=primary_rel_path or self.primary_rel_path,
            created=datetime.datetime.now(datetime.UTC),
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

    async def abs_path(self, rel_path: str | None = None) -> pathlib.Path | None:
        """Construct the absolute path using the required draft_revision."""
        base_dir = util.get_release_candidate_draft_dir()
        project_part = self.project_name
        version_part = self.version_name
        revision_part = self.draft_revision

        # Determine the relative path part
        rel_path_part: str | None = None
        if rel_path is not None:
            rel_path_part = rel_path
        elif self.primary_rel_path is not None:
            rel_path_part = self.primary_rel_path

        # Construct the absolute path
        abs_path_parts: list[str | pathlib.Path] = [base_dir, project_part, version_part, revision_part]
        if isinstance(rel_path_part, str):
            abs_path_parts.append(rel_path_part)
        return pathlib.Path(*abs_path_parts)

    async def clear(self, primary_rel_path: str | None = None) -> None:
        async with db.session() as data:
            stmt = sqlmodel.delete(models.CheckResult).where(
                db.validate_instrumented_attribute(models.CheckResult.release_name) == self.release_name,
                db.validate_instrumented_attribute(models.CheckResult.checker) == self.checker,
                db.validate_instrumented_attribute(models.CheckResult.primary_rel_path) == primary_rel_path,
            )
            await data.execute(stmt)
            await data.commit()

    async def exception(self, message: str, data: Any, primary_rel_path: str | None = None) -> models.CheckResult:
        return await self._add(models.CheckResultStatus.EXCEPTION, message, data, primary_rel_path=primary_rel_path)

    async def failure(self, message: str, data: Any, primary_rel_path: str | None = None) -> models.CheckResult:
        return await self._add(models.CheckResultStatus.FAILURE, message, data, primary_rel_path=primary_rel_path)

    async def success(self, message: str, data: Any, primary_rel_path: str | None = None) -> models.CheckResult:
        return await self._add(models.CheckResultStatus.SUCCESS, message, data, primary_rel_path=primary_rel_path)

    async def warning(self, message: str, data: Any, primary_rel_path: str | None = None) -> models.CheckResult:
        return await self._add(models.CheckResultStatus.WARNING, message, data, primary_rel_path=primary_rel_path)


def function_key(func: Callable[..., Any]) -> str:
    return func.__module__ + "." + func.__name__


def with_model(cls: type[pydantic.BaseModel]) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to specify the parameters for a check."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def wrapper(data_dict: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
            model_instance = cls(**data_dict)
            return await func(model_instance, *args, **kwargs)

        return wrapper

    return decorator
