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

import asyncio
import binascii
import contextlib
import dataclasses
import hashlib
import pathlib
import shutil
import tempfile
from collections.abc import AsyncGenerator, Callable, Mapping, Sequence
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
import atr.db.models as models

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


@dataclasses.dataclass
class FileStat:
    path: str
    modified: int
    size: int
    permissions: int
    is_file: bool
    is_dir: bool


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


def abs_path_to_release_and_rel_path(abs_path: str) -> tuple[str, str]:
    """Return the release name and relative path for a given path."""
    conf = config.get()
    phase_dir = pathlib.Path(conf.PHASE_STORAGE_DIR)
    phase_sub_dir = pathlib.Path(abs_path).relative_to(phase_dir)
    # Skip the first component, which is the phase name
    # The next two components are the project name and version name
    project_name = phase_sub_dir.parts[1]
    version_name = phase_sub_dir.parts[2]
    return models.release_name(project_name, version_name), str(pathlib.Path(*phase_sub_dir.parts[3:]))


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


async def content_list(phase_subdir: pathlib.Path, project_name: str, version_name: str) -> AsyncGenerator[FileStat]:
    """List all the files in the given path."""
    base_path = phase_subdir / project_name / version_name
    for path in await paths_recursive(base_path):
        stat = await aiofiles.os.stat(base_path / path)
        yield FileStat(
            path=str(path),
            modified=int(stat.st_mtime),
            size=stat.st_size,
            permissions=stat.st_mode,
            is_file=bool(stat.st_mode & 0o0100000),
            is_dir=bool(stat.st_mode & 0o040000),
        )


async def file_sha3(path: str) -> str:
    """Compute SHA3-256 hash of a file."""
    sha3 = hashlib.sha3_256()
    async with aiofiles.open(path, "rb") as f:
        while chunk := await f.read(4096):
            sha3.update(chunk)
    return sha3.hexdigest()


def get_phase_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR)


def get_release_candidate_draft_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR) / "release-candidate-draft"


def get_release_candidate_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR) / "release-candidate"


def get_release_preview_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR) / "release-preview"


def get_release_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR) / "release"


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


def release_directory(release: models.Release) -> pathlib.Path:
    """Determine the filesystem directory for a given release based on its phase."""
    phase = release.phase
    try:
        project_name, version_name = release.name.rsplit("-", 1)
    except ValueError:
        raise base.ASFQuartException(f"Invalid release name format '{release.name}'", 500)

    base_dir: pathlib.Path | None = None
    match phase:
        case models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
            base_dir = get_release_candidate_draft_dir()
        case models.ReleasePhase.RELEASE_CANDIDATE_BEFORE_VOTE | models.ReleasePhase.RELEASE_CANDIDATE_DURING_VOTE:
            base_dir = get_release_candidate_dir()
        case models.ReleasePhase.RELEASE_PREVIEW:
            base_dir = get_release_preview_dir()
        case models.ReleasePhase.RELEASE_BEFORE_ANNOUNCEMENT | models.ReleasePhase.RELEASE_AFTER_ANNOUNCEMENT:
            base_dir = get_release_dir()
        # NOTE: Do NOT add "case _" here

    return base_dir / project_name / version_name


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


def user_releases(asf_uid: str, releases: Sequence[models.Release]) -> list[models.Release]:
    """Return a list of releases for which the user is a committee member or committer."""
    # TODO: This should probably be a session method instead
    user_releases = []
    for release in releases:
        if release.committee is None:
            continue
        if (asf_uid in release.committee.committee_members) or (asf_uid in release.committee.committers):
            user_releases.append(release)
    return user_releases


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


@contextlib.asynccontextmanager
async def async_temporary_directory(
    suffix: str | None = None, prefix: str | None = None, dir: str | pathlib.Path | None = None
) -> AsyncGenerator[pathlib.Path]:
    """Create an async temporary directory similar to tempfile.TemporaryDirectory."""
    temp_dir_path: str = await asyncio.to_thread(tempfile.mkdtemp, suffix=suffix, prefix=prefix, dir=dir)
    try:
        yield pathlib.Path(temp_dir_path)
    finally:
        await asyncio.to_thread(shutil.rmtree, temp_dir_path, ignore_errors=True)


async def read_file_for_viewer(full_path: pathlib.Path, max_size: int) -> tuple[str | None, bool, bool, str | None]:
    """Read file content for viewer."""
    content: str | None = None
    is_text = False
    is_truncated = False
    error_message: str | None = None

    try:
        if not await aiofiles.os.path.exists(full_path):
            return None, False, False, "File does not exist"
        if not await aiofiles.os.path.isfile(full_path):
            return None, False, False, "Path is not a file"

        file_size = await aiofiles.os.path.getsize(full_path)
        read_size = min(file_size, max_size)

        if file_size > max_size:
            is_truncated = True

        if file_size == 0:
            is_text = True
            content = "(Empty file)"
            raw_content = b""
        else:
            async with aiofiles.open(full_path, "rb") as f:
                raw_content = await f.read(read_size)

        if file_size > 0:
            try:
                if b"\x00" in raw_content:
                    raise UnicodeDecodeError("utf-8", b"", 0, 1, "Null byte found")
                content = raw_content.decode("utf-8")
                is_text = True
            except UnicodeDecodeError:
                is_text = False
                content = _generate_hexdump(raw_content)

    except Exception as e:
        error_message = f"An error occurred reading the file: {e!s}"

    return content, is_text, is_truncated, error_message


def _generate_hexdump(data: bytes) -> str:
    """Generate a formatted hexdump string from bytes."""
    hex_lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = binascii.hexlify(chunk).decode("ascii")
        hex_part = hex_part.ljust(32)
        hex_part_spaced = " ".join(hex_part[j : j + 2] for j in range(0, len(hex_part), 2))
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        line_num = f"{i:08x}"
        hex_lines.append(f"{line_num}  {hex_part_spaced}  |{ascii_part}|")
    return "\n".join(hex_lines)
