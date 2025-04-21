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
import logging
import pathlib
import re
import shutil
import tarfile
import tempfile
import uuid
import zipfile
from collections.abc import AsyncGenerator, Callable, Generator, ItemsView, Mapping, Sequence
from typing import Annotated, Any, TypeVar

import aiofiles.os
import asfquart
import asfquart.base as base
import asfquart.session as session
import jinja2
import pydantic
import pydantic_core
import quart
import quart_wtf
import quart_wtf.typing
import wtforms

# NOTE: The atr.db module imports this module
# Therefore, this module must not import atr.db
import atr.config as config
import atr.db.models as models
import atr.user as user

F = TypeVar("F", bound="QuartFormTyped")
T = TypeVar("T")
VT = TypeVar("VT")

_LOGGER = logging.getLogger(__name__)


class DictRootModel(pydantic.RootModel[dict[str, VT]]):
    def __iter__(self) -> Generator[tuple[str, VT]]:
        yield from self.root.items()

    def items(self) -> ItemsView[str, VT]:
        return self.root.items()

    def get(self, key: str) -> VT | None:
        return self.root.get(key)

    def __len__(self) -> int:
        return len(self.root)


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


async def archive_listing(file_path: pathlib.Path) -> list[str] | None:
    """Attempt to list contents of supported archive files."""
    if not await aiofiles.os.path.isfile(file_path):
        return None

    with contextlib.suppress(Exception):
        if file_path.name.endswith((".tar.gz", ".tgz")):

            def _read_tar() -> list[str] | None:
                with contextlib.suppress(tarfile.ReadError, EOFError, ValueError, OSError):
                    with tarfile.open(file_path, mode="r:*") as tf:
                        return sorted(tf.getnames())
                return None

            return await asyncio.to_thread(_read_tar)

        elif file_path.name.endswith(".zip"):

            def _read_zip() -> list[str] | None:
                with contextlib.suppress(zipfile.BadZipFile, EOFError, ValueError, OSError):
                    with zipfile.ZipFile(file_path, "r") as zf:
                        return sorted(zf.namelist())
                return None

            return await asyncio.to_thread(_read_zip)

    return None


def as_url(func: Callable, **kwargs: Any) -> str:
    """Return the URL for a function."""
    if isinstance(func, jinja2.runtime.Undefined):
        _LOGGER.exception("Undefined route in the calling template")
        raise base.ASFQuartException("Undefined route", 500)
    try:
        annotations = func.__annotations__
    except AttributeError as e:
        _LOGGER.error(f"Cannot get annotations for {func} (type: {type(func)})")
        raise base.ASFQuartException(f"Cannot get annotations for {func} (type: {type(func)})", 500) from e
    return quart.url_for(annotations["endpoint"], **kwargs)


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


async def content_list(
    phase_subdir: pathlib.Path, project_name: str, version_name: str, revision_name: str | None = None
) -> AsyncGenerator[FileStat]:
    """List all the files in the given path."""
    base_path = phase_subdir / project_name / version_name
    if (phase_subdir.name == "release-candidate-draft") and (revision_name is None):
        raise ValueError("A revision name is required for release candidate draft content listing")
    if revision_name:
        base_path = base_path / revision_name
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


async def create_hard_link_clone(source_dir: pathlib.Path, dest_dir: pathlib.Path) -> None:
    """Recursively create a clone of source_dir in dest_dir using hard links for files."""
    # TODO: We're currently using cp -al instead
    # Ensure source exists and is a directory
    if not await aiofiles.os.path.isdir(source_dir):
        raise ValueError(f"Source path is not a directory or does not exist: {source_dir}")

    # Create destination directory
    await aiofiles.os.makedirs(dest_dir, exist_ok=False)

    async def _clone_recursive(current_source: pathlib.Path, current_dest: pathlib.Path) -> None:
        for entry in await aiofiles.os.scandir(current_source):
            source_entry_path = current_source / entry.name
            dest_entry_path = current_dest / entry.name

            try:
                if entry.is_dir():
                    await aiofiles.os.makedirs(dest_entry_path, exist_ok=True)
                    await _clone_recursive(source_entry_path, dest_entry_path)
                elif entry.is_file():
                    await aiofiles.os.link(source_entry_path, dest_entry_path)
                # Ignore other types like symlinks for now
            except OSError as e:
                _LOGGER.error(f"Error cloning {source_entry_path} to {dest_entry_path}: {e}")
                raise

    await _clone_recursive(source_dir, dest_dir)


async def file_sha3(path: str) -> str:
    """Compute SHA3-256 hash of a file."""
    sha3 = hashlib.sha3_256()
    async with aiofiles.open(path, "rb") as f:
        while chunk := await f.read(4096):
            sha3.update(chunk)
    return sha3.hexdigest()


async def get_asf_id_or_die() -> str:
    web_session = await session.read()
    if web_session is None or web_session.uid is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)
    return web_session.uid


def get_phase_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR)


def get_release_candidate_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR) / "release-candidate"


def get_release_candidate_draft_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR) / "release-candidate-draft"


def get_release_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR) / "release"


def get_release_preview_dir() -> pathlib.Path:
    return pathlib.Path(config.get().PHASE_STORAGE_DIR) / "release-preview"


def is_user_viewing_as_admin(uid: str | None) -> bool:
    """Check whether a user is currently viewing the site with active admin privileges."""
    if not user.is_admin(uid):
        return False

    try:
        app = asfquart.APP
        if not hasattr(app, "app_id") or not isinstance(app.app_id, str):
            _LOGGER.error("Cannot get valid app_id to read session for admin view check")
            return True

        cookie_id = app.app_id
        session_dict = quart.session.get(cookie_id, {})
        is_downgraded = session_dict.get("downgrade_admin_to_user", False)
        return not is_downgraded
    except Exception:
        _LOGGER.exception(f"Error checking admin downgrade session status for {uid}")
        return True


async def number_of_release_files(release: models.Release) -> int:
    """Return the number of files in a release."""
    path_project = release.project.name
    path_version = release.version
    path_revision = release.revision or "force-error"
    match release.phase:
        case models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
            path = get_release_candidate_draft_dir() / path_project / path_version / path_revision
        case models.ReleasePhase.RELEASE_CANDIDATE:
            path = get_release_candidate_dir() / path_project / path_version
        case models.ReleasePhase.RELEASE_PREVIEW:
            path = get_release_preview_dir() / path_project / path_version / path_revision
        case models.ReleasePhase.RELEASE_AFTER_ANNOUNCEMENT:
            path = get_release_dir() / path_project / path_version
        case _:
            raise ValueError(f"Unknown release phase: {release.phase}")
    return len(await paths_recursive(path))


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


def permitted_vote_recipients(asf_uid: str) -> list[str]:
    test_list = "user-tests"
    return [
        # f"dev@{committee.name}.apache.org",
        # f"private@{committee.name}.apache.org",
        f"{test_list}@tooling.apache.org",
        f"{asf_uid}@apache.org",
    ]


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
        case models.ReleasePhase.RELEASE_CANDIDATE:
            base_dir = get_release_candidate_dir()
        case models.ReleasePhase.RELEASE_PREVIEW:
            base_dir = get_release_preview_dir()
        case models.ReleasePhase.RELEASE_AFTER_ANNOUNCEMENT:
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


async def update_atomic_symlink(link_path: pathlib.Path, target_path: pathlib.Path | str) -> None:
    """Atomically update or create a symbolic link at link_path pointing to target_path."""
    target_str = str(target_path)

    # Generate a temporary path name for the new link
    link_dir = link_path.parent
    temp_link_path = link_dir / f".{link_path.name}.{uuid.uuid4()}.tmp"

    try:
        await aiofiles.os.symlink(target_str, temp_link_path)
        # Atomically rename the temporary link to the final link path
        # This overwrites link_path if it exists
        await aiofiles.os.rename(temp_link_path, link_path)
        _LOGGER.info(f"Atomically updated symlink {link_path} -> {target_str}")
    except Exception as e:
        # Don't bother with _LOGGER.exception here
        _LOGGER.error(f"Failed to update atomic symlink {link_path} -> {target_str}: {e}")
        # Clean up temporary link if rename failed
        try:
            await aiofiles.os.remove(temp_link_path)
        except FileNotFoundError:
            # TODO: Use with contextlib.suppress(FileNotFoundError) for these sorts of blocks?
            pass
        raise


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


def validate_vote_duration(form: wtforms.Form, field: wtforms.IntegerField) -> None:
    """Checks if the value is 0 or between 72 and 144."""
    if not ((field.data == 0) or (72 <= field.data <= 144)):
        raise wtforms.validators.ValidationError("Minimum voting period must be 0 hours, or between 72 and 144 hours")


def version_name_error(version_name: str) -> str | None:
    """Check if the given version name is valid."""
    if version_name == "":
        return "Must not be empty"
    if version_name.lower() == "version":
        return "Must not be 'version'"
    if not re.match(r"^[a-zA-Z0-9]", version_name):
        return "Must start with a letter or number"
    if not re.search(r"[a-zA-Z0-9]$", version_name):
        return "Must end with a letter or number"
    if re.search(r"[+.-]{2,}", version_name):
        return "Must not contain multiple consecutive plus, full stop, or hyphen"
    if not re.match(r"^[a-zA-Z0-9+.-]+$", version_name):
        return "Must contain only letters, numbers, plus, full stop, or hyphen"
    return None


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
