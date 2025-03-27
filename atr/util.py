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
import functools
import hashlib
import pathlib
from collections.abc import Callable, Mapping
from typing import Annotated, Any, TypeVar

import aiofiles.os
import asfquart.base as base
import asfquart.session as session
import pydantic
import pydantic_core
import quart
import quart_wtf
import quart_wtf.typing

import atr.config as config

F = TypeVar("F", bound="QuartFormTyped")
T = TypeVar("T")


async def get_asf_id_or_die() -> str:
    web_session = await session.read()
    if web_session is None or web_session.uid is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)
    return web_session.uid


# from https://github.com/pydantic/pydantic/discussions/8755#discussioncomment-8417979
@dataclasses.dataclass
class DictToList:
    key: str

    def __get_pydantic_core_schema__(
        self,
        source_type: Any,
        handler: pydantic.GetCoreSchemaHandler,
    ) -> pydantic_core.CoreSchema:
        adapter = _get_dict_to_list_inner_type_adapter(source_type, self.key)

        return pydantic_core.core_schema.no_info_before_validator_function(
            _get_dict_to_list_validator(adapter, self.key),
            handler(source_type),
        )


class QuartFormTyped(quart_wtf.QuartForm):
    """Quart form with type annotations."""

    @classmethod
    async def create_form(
        cls: type[F],
        formdata: object | quart_wtf.typing.FormData = quart_wtf.form._Auto,
        obj: Any | None = None,
        prefix: str = "",
        data: dict | None = None,
        meta: dict | None = None,
        **kwargs: dict[str, Any],
    ) -> F:
        """Create a form instance with typing."""
        form = await super().create_form(formdata, obj, prefix, data, meta, **kwargs)
        if not isinstance(form, cls):
            raise TypeError(f"Form is not of type {cls.__name__}")
        return form


def as_url(func: Callable, **kwargs: Any) -> str:
    """Return the URL for a function."""
    return quart.url_for(func.__annotations__["endpoint"], **kwargs)


def compute_sha3_256(file_data: bytes) -> str:
    """Compute SHA3-256 hash of file data."""
    return hashlib.sha3_256(file_data).hexdigest()


async def compute_sha512(file_path: pathlib.Path) -> str:
    """Compute SHA-512 hash of a file."""
    sha512 = hashlib.sha512()
    async with aiofiles.open(file_path, "rb") as f:
        while chunk := await f.read(4096):
            sha512.update(chunk)
    return sha512.hexdigest()


async def file_sha3(path: str) -> str:
    """Compute SHA3-256 hash of a file."""
    sha3 = hashlib.sha3_256()
    async with aiofiles.open(path, "rb") as f:
        while chunk := await f.read(4096):
            sha3.update(chunk)
    return sha3.hexdigest()


@functools.cache
def get_admin_users() -> set[str]:
    return set(config.get().ADMIN_USERS)


def get_phase_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR)


def get_release_candidate_draft_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR) / "release-candidate-draft"


def get_release_candidate_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR) / "release-candidate"


def get_release_draft_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR) / "release-draft"


def get_release_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR) / "release"


def is_admin(user_id: str | None) -> bool:
    """Check whether a user is an admin."""
    if user_id is None:
        return False
    return user_id in get_admin_users()


async def paths_recursive(base_path: pathlib.Path, sort: bool = True) -> list[pathlib.Path]:
    """List all paths recursively in alphabetical order from a given base path."""
    paths: list[pathlib.Path] = []

    async def _recursive_list(current_path: pathlib.Path, relative_path: pathlib.Path = pathlib.Path()) -> None:
        try:
            entries = await aiofiles.os.listdir(current_path)
            for entry in entries:
                entry_path = current_path / entry
                entry_rel_path = relative_path / entry

                try:
                    stat_info = await aiofiles.os.stat(entry_path)
                    # If the entry is a directory, recurse into it
                    if stat_info.st_mode & 0o040000:
                        await _recursive_list(entry_path, entry_rel_path)
                    else:
                        paths.append(entry_rel_path)
                except (FileNotFoundError, PermissionError):
                    continue
        except FileNotFoundError:
            pass

    await _recursive_list(base_path)
    if sort is True:
        paths.sort()
    return paths


def unwrap(value: T | None, error_message: str = "unexpected None when unwrapping value") -> T:
    """
    Will unwrap the given value or raise a ValueError if it is None

    :param value: the optional value to unwrap
    :param error_message: the error message when failing to unwrap
    :return: the value or a ValueError if it is None
    """
    if value is None:
        raise ValueError(error_message)
    else:
        return value


def validate_as_type(value: Any, t: type[T]) -> T:
    """Validate the given value as the given type."""
    if not isinstance(value, t):
        raise ValueError(f"Expected {t}, got {type(value)}")
    return value


def _get_dict_to_list_inner_type_adapter(source_type: Any, key: str) -> pydantic.TypeAdapter[dict[Any, Any]]:
    root_adapter = pydantic.TypeAdapter(source_type)
    schema = root_adapter.core_schema

    # support further nesting of model classes
    if schema["type"] == "definitions":
        schema = schema["schema"]

    assert schema["type"] == "list"
    assert (item_schema := schema["items_schema"])
    assert item_schema["type"] == "model"
    assert (cls := item_schema["cls"])  # noqa: RUF018

    fields = cls.model_fields

    assert (key_field := fields.get(key))  # noqa: RUF018
    assert (other_fields := {k: v for k, v in fields.items() if k != key})  # noqa: RUF018

    model_name = f"{cls.__name__}Inner"

    # Create proper field definitions for create_model
    inner_model = pydantic.create_model(model_name, **{k: (v.annotation, v) for k, v in other_fields.items()})  # type: ignore
    return pydantic.TypeAdapter(dict[Annotated[str, key_field], inner_model])  # type: ignore


def _get_dict_to_list_validator(inner_adapter: pydantic.TypeAdapter[dict[Any, Any]], key: str) -> Any:
    def validator(val: Any) -> Any:
        import pydantic.fields as fields

        if isinstance(val, dict):
            validated = inner_adapter.validate_python(val)

            # need to get the alias of the field in the nested model
            # as this will be fed into the actual model class
            def get_alias(field_name: str, field_infos: Mapping[str, fields.FieldInfo]) -> Any:
                field = field_infos[field_name]
                return field.alias if field.alias else field_name

            return [
                {key: k, **{get_alias(f, v.model_fields): getattr(v, f) for f in v.model_fields}}
                for k, v in validated.items()
            ]

        return val

    return validator
