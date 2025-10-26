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
import base64
import binascii
import contextlib
import dataclasses
import datetime
import hashlib
import json
import os
import pathlib
import re
import tarfile
import tempfile
import uuid
import zipfile
from collections.abc import AsyncGenerator, Callable, Iterable, Sequence
from typing import Any, Final, TypeVar

import aiofiles.os
import aiohttp
import aioshutil
import asfquart
import asfquart.base as base
import asfquart.session as session
import gitignore_parser
import jinja2
import quart
import wtforms

# NOTE: The atr.db module imports this module
# Therefore, this module must not import atr.db
import atr.config as config
import atr.forms as forms
import atr.ldap as ldap
import atr.log as log
import atr.models.sql as sql
import atr.registry as registry
import atr.user as user

T = TypeVar("T")

USER_TESTS_ADDRESS: Final[str] = "user-tests@tooling.apache.org"


class SshFingerprintError(ValueError):
    pass


@dataclasses.dataclass
class FileStat:
    path: str
    modified: int
    size: int
    permissions: int
    is_file: bool
    is_dir: bool


class FetchError(RuntimeError):
    pass


async def archive_listing(file_path: pathlib.Path) -> list[str] | None:
    """Attempt to list contents of supported archive files."""
    if not await aiofiles.os.path.isfile(file_path):
        return None

    with contextlib.suppress(Exception):
        if file_path.name.endswith((".tar.gz", ".tgz")):

            def _read_tar() -> list[str] | None:
                with contextlib.suppress(tarfile.ReadError, EOFError, ValueError, OSError):
                    with tarfile.open(file_path, mode="r:*") as tf:
                        # TODO: Skip metadata files
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
        log.exception("Undefined route in the calling template")
        raise RuntimeError("Undefined route in the calling template")
    try:
        annotations = func.__annotations__
    except AttributeError as e:
        log.error(f"Cannot get annotations for {func} (type: {type(func)})")
        raise RuntimeError(f"Cannot get annotations for {func} (type: {type(func)})") from e
    return quart.url_for(annotations["endpoint"], **kwargs)


def asf_uid_from_email(email: str) -> str | None:
    ldap_params = ldap.SearchParameters(email_query=email)
    ldap.search(ldap_params)
    if not (ldap_params.results_list and ("uid" in ldap_params.results_list[0])):
        return None
    ldap_uid_val = ldap_params.results_list[0]["uid"]
    return ldap_uid_val[0] if isinstance(ldap_uid_val, list) else ldap_uid_val


async def asf_uid_from_uids(
    uids: list[str], use_ldap: bool = True, ldap_data: dict[str, str] | None = None
) -> str | None:
    # Determine ASF UID if not provided
    emails = []
    for uid_str in uids:
        # This returns a lower case email address, no matter what the case of the input UID
        if email := email_from_uid(uid_str):
            if email.endswith("@apache.org"):
                return email.removesuffix("@apache.org")
            emails.append(email)
    # We did not find a direct @apache.org email address
    # Therefore, search LDAP data, either cached or directly
    if ldap_data is not None:
        # Use cached LDAP data
        for email in emails:
            if email in ldap_data:
                return ldap_data[email]
        return None
    if use_ldap:
        # Search LDAP directly
        for email in emails:
            if asf_uid := await asyncio.to_thread(asf_uid_from_email, email):
                return asf_uid
    return None


@contextlib.asynccontextmanager
async def async_temporary_directory(
    suffix: str | None = None, prefix: str | None = None, dir: str | pathlib.Path | None = None
) -> AsyncGenerator[pathlib.Path]:
    """Create an async temporary directory similar to tempfile.TemporaryDirectory."""
    temp_dir_path: str = await asyncio.to_thread(tempfile.mkdtemp, suffix=suffix, prefix=prefix, dir=dir)
    try:
        yield pathlib.Path(temp_dir_path)
    finally:
        try:
            await aioshutil.rmtree(temp_dir_path)  # type: ignore[call-arg]
        except Exception:
            pass


def chmod_directories(path: pathlib.Path, permissions: int = 0o755) -> None:
    os.chmod(path, permissions)
    for dir_path in path.rglob("*"):
        if dir_path.is_dir():
            os.chmod(dir_path, permissions)


def committee_is_standing(committee_name: str) -> bool:
    return committee_name in registry.STANDING_COMMITTEES


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
    if phase_subdir.name in {"release-candidate-draft", "release-preview"}:
        if revision_name is None:
            raise ValueError("A revision name is required for release candidate draft or preview content listing")
    if revision_name:
        base_path = base_path / revision_name
    async for path in paths_recursive(base_path):
        stat = await aiofiles.os.stat(base_path / path)
        yield FileStat(
            path=str(path),
            modified=int(stat.st_mtime),
            size=stat.st_size,
            permissions=stat.st_mode,
            is_file=bool(stat.st_mode & 0o0100000),
            is_dir=bool(stat.st_mode & 0o040000),
        )


async def create_hard_link_clone(
    source_dir: pathlib.Path,
    dest_dir: pathlib.Path,
    do_not_create_dest_dir: bool = False,
    exist_ok: bool = False,
    dry_run: bool = False,
) -> None:
    """Recursively create a clone of source_dir in dest_dir using hard links for files."""
    await _create_hard_link_clone_checks(source_dir, dest_dir, do_not_create_dest_dir, exist_ok, dry_run)

    async def _clone_recursive(current_source: pathlib.Path, current_dest: pathlib.Path) -> None:
        for entry in await aiofiles.os.scandir(current_source):
            source_entry_path = current_source / entry.name
            dest_entry_path = current_dest / entry.name

            try:
                if entry.is_dir():
                    await aiofiles.os.makedirs(dest_entry_path, exist_ok=True)
                    await _clone_recursive(source_entry_path, dest_entry_path)
                elif entry.is_file():
                    if not dry_run:
                        await aiofiles.os.link(source_entry_path, dest_entry_path)
                    elif dry_run and (await aiofiles.os.path.exists(dest_entry_path)):
                        raise ValueError(f"Destination path exists: {dest_entry_path}")
                # Ignore other types like symlinks for now
            except OSError as e:
                log.error(f"Error cloning {source_entry_path} to {dest_entry_path}: {e}")
                raise

    await _clone_recursive(source_dir, dest_dir)


def create_path_matcher(lines: Iterable[str], full_path: pathlib.Path, base_dir: pathlib.Path) -> Callable[[str], bool]:
    rules = []
    negation = False
    for line_no, line in enumerate(lines, start=1):
        rule = gitignore_parser.rule_from_pattern(line.rstrip("\n"), base_path=base_dir, source=(full_path, line_no))
        if rule:
            rules.append(rule)
            if rule.negation:
                negation = True
    if not negation:
        return lambda file_path: any(r.match(file_path) for r in rules)
    return lambda file_path: gitignore_parser.handle_negation(file_path, rules)


def is_dev_environment() -> bool:
    conf = config.get()
    for development_host in ("127.0.0.1", "localhost.apache.org"):
        if (conf.APP_HOST == development_host) or conf.APP_HOST.startswith(f"{development_host}:"):
            return True
    return False


def email_from_uid(uid: str) -> str | None:
    if m := re.search(r"<([^>]+)>", uid):
        return m.group(1).lower()
    elif m := re.search(r"^([^@ ]+)@apache.org$", uid):
        return uid
    return None


async def email_mid_from_thread_id(thread_id: str) -> tuple[str, str]:
    async for _thread_id, msg_json in thread_messages(thread_id):
        # The .get("to", "") value may be redacted, e.g. "us...@tooling.apache.org"
        # Therefore use .get("forum", "")
        email_to = msg_json.get("forum", "")
        if email_to is None:
            raise RuntimeError(f"Cannot find email address for {thread_id}")
        # This is delimited by angle brackets, e.g. "<1234567890@apache.org>"
        message_id = msg_json.get("message-id", "")
        if message_id is None:
            raise RuntimeError(f"Cannot find message ID for {thread_id}")
        return email_to, message_id
    raise RuntimeError(f"Cannot find any messages in {thread_id}")


async def email_to_uid_map() -> dict[str, str]:
    def get(entry: dict, prop: str) -> str | None:
        if prop in entry:
            values = entry[prop]
            if values:
                return values[0]
        return None

    # Get all email addresses in LDAP
    conf = config.AppConfig()
    bind_dn = conf.LDAP_BIND_DN
    bind_password = conf.LDAP_BIND_PASSWORD
    ldap_params = ldap.SearchParameters(
        uid_query="*",
        bind_dn_from_config=bind_dn,
        bind_password_from_config=bind_password,
        email_only=True,
    )
    await asyncio.to_thread(ldap.search, ldap_params)

    # Map the LDAP addresses to Apache UIDs
    email_to_uid = {}
    for entry in ldap_params.results_list:
        uid = entry.get("uid", [""])[0]
        if mail := get(entry, "mail"):
            email_to_uid[mail.lower()] = uid.lower()
        if alt_email := get(entry, "asf-altEmail"):
            email_to_uid[alt_email.lower()] = uid.lower()
        if committer_email := get(entry, "asf-committer-email"):
            email_to_uid[committer_email.lower()] = uid.lower()
    return email_to_uid


async def file_sha3(path: str) -> str:
    """Compute SHA3-256 hash of a file."""
    sha3 = hashlib.sha3_256()
    async with aiofiles.open(path, "rb") as f:
        while chunk := await f.read(4096):
            sha3.update(chunk)
    return sha3.hexdigest()


def format_datetime(dt_obj: datetime.datetime | int) -> str:
    """Format a datetime object or Unix timestamp into a human readable datetime string."""
    # Integers are unix timestamps
    if isinstance(dt_obj, int):
        dt_obj = datetime.datetime.fromtimestamp(dt_obj, tz=datetime.UTC)

    # Ensure UTC native timezone awareness
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=datetime.UTC)
    else:
        # Convert to UTC if not already
        dt_obj = dt_obj.astimezone(datetime.UTC)

    return dt_obj.strftime("%Y-%m-%d %H:%M:%S")


def format_file_size(size_in_bytes: int) -> str:
    """Format a file size with appropriate units and comma-separated digits."""
    # Format the raw bytes with commas
    formatted_bytes = f"{size_in_bytes:,}"

    # Calculate the appropriate unit
    if size_in_bytes >= 1_000_000_000:
        size_in_gb = size_in_bytes // 1_000_000_000
        return f"{size_in_gb:,} GB ({formatted_bytes} bytes)"
    elif size_in_bytes >= 1_000_000:
        size_in_mb = size_in_bytes // 1_000_000
        return f"{size_in_mb:,} MB ({formatted_bytes} bytes)"
    elif size_in_bytes >= 1_000:
        size_in_kb = size_in_bytes // 1_000
        return f"{size_in_kb:,} KB ({formatted_bytes} bytes)"
    else:
        return f"{formatted_bytes} bytes"


def format_permissions(mode: int) -> str:
    """Format Unix file permissions in ls -l style."""
    # File type
    if mode & 0o040000:
        # Directory
        perms = "d"
    elif mode & 0o0100000:
        # Regular file
        perms = "-"
    elif mode & 0o020000:
        # Character special
        perms = "c"
    elif mode & 0o060000:
        # Block special
        perms = "b"
    elif mode & 0o010000:
        # FIFO
        perms = "p"
    elif mode & 0o0140000:
        # Socket
        perms = "s"
    else:
        perms = "?"

    # Owner permissions
    perms += "r" if mode & 0o400 else "-"
    perms += "w" if mode & 0o200 else "-"
    perms += "x" if mode & 0o100 else "-"

    # Group permissions
    perms += "r" if mode & 0o040 else "-"
    perms += "w" if mode & 0o020 else "-"
    perms += "x" if mode & 0o010 else "-"

    # Others permissions
    perms += "r" if mode & 0o004 else "-"
    perms += "w" if mode & 0o002 else "-"
    perms += "x" if mode & 0o001 else "-"

    return perms


async def get_asf_id_or_die() -> str:
    web_session = await session.read()
    if web_session is None or web_session.uid is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)
    return web_session.uid


def get_downloads_dir() -> pathlib.Path:
    return pathlib.Path(config.get().DOWNLOADS_STORAGE_DIR)


def get_finished_dir() -> pathlib.Path:
    return pathlib.Path(config.get().FINISHED_STORAGE_DIR)


async def get_release_stats(release: sql.Release) -> tuple[int, int, str]:
    """Calculate file count, total byte size, and formatted size for a release."""
    base_dir = release_directory(release)
    count = 0
    total_bytes = 0
    try:
        async for rel_path in paths_recursive(base_dir):
            full_path = base_dir / rel_path
            if await aiofiles.os.path.isfile(full_path):
                try:
                    size = await aiofiles.os.path.getsize(full_path)
                    count += 1
                    total_bytes += size
                except OSError:
                    ...
    except FileNotFoundError:
        ...

    formatted_size = format_file_size(total_bytes)
    return count, total_bytes, formatted_size


def get_tmp_dir() -> pathlib.Path:
    # This must be on the same filesystem as the other state subdirectories
    return pathlib.Path(config.get().STATE_DIR) / "tmp"


def get_unfinished_dir() -> pathlib.Path:
    return pathlib.Path(config.get().UNFINISHED_STORAGE_DIR)


async def get_urls_as_completed(urls: Sequence[str]) -> AsyncGenerator[tuple[str, int | str | None, bytes]]:
    """GET a list of URLs in parallel and yield (url, status, content_bytes) as they become available."""
    async with aiohttp.ClientSession() as session:

        async def _fetch(one_url: str) -> tuple[str, int | str | None, bytes]:
            try:
                async with session.get(one_url) as resp:
                    try:
                        resp.raise_for_status()
                        return (str(resp.url), resp.status, await resp.read())
                    except aiohttp.ClientResponseError as e:
                        url = str(e.request_info.real_url)
                        if e.status == 200:
                            return (url, str(e), b"")
                        return (url, e.status, b"")
            except Exception as exc:
                return ("", str(exc), b"")

        tasks = [asyncio.create_task(_fetch(u)) for u in urls]
        for future in asyncio.as_completed(tasks):
            yield await future


async def has_files(release: sql.Release) -> bool:
    """Check if a release has any files."""
    base_dir = release_directory(release)
    try:
        async for rel_path in paths_recursive(base_dir):
            full_path = base_dir / rel_path
            if await aiofiles.os.path.isfile(full_path):
                return True
    except FileNotFoundError:
        ...
    return False


async def is_dir_resolve(path: pathlib.Path) -> pathlib.Path | None:
    try:
        resolved_path = await asyncio.to_thread(path.resolve)
        if not await aiofiles.os.path.isdir(resolved_path):
            return None
    except (FileNotFoundError, OSError):
        return None
    return resolved_path


def is_user_viewing_as_admin(uid: str | None) -> bool:
    """Check whether a user is currently viewing the site with active admin privileges."""
    if not user.is_admin(uid):
        return False

    try:
        app = asfquart.APP
        if not hasattr(app, "app_id") or not isinstance(app.app_id, str):
            log.error("Cannot get valid app_id to read session for admin view check")
            return True

        cookie_id = app.app_id
        session_dict = quart.session.get(cookie_id, {})
        is_downgraded = session_dict.get("downgrade_admin_to_user", False)
        return not is_downgraded
    except Exception:
        log.exception(f"Error checking admin downgrade session status for {uid}")
        return True


def key_ssh_fingerprint(ssh_key_string: str) -> str:
    try:
        return key_ssh_fingerprint_core(ssh_key_string)
    except ValueError as e:
        raise SshFingerprintError(str(e)) from e


def key_ssh_fingerprint_core(ssh_key_string: str) -> str:
    # The format should be as in *.pub or authorized_keys files
    # I.e. TYPE DATA COMMENT
    ssh_key_parts = ssh_key_string.strip().split()
    if len(ssh_key_parts) >= 2:
        # We discard the type, which is ssh_key_parts[0]
        key_data = ssh_key_parts[1]
        # We discard the comment, which is ssh_key_parts[2]

        # Standard fingerprint calculation
        try:
            decoded_key_data = base64.b64decode(key_data)
        except binascii.Error as e:
            raise ValueError(f"Invalid base64 encoding in key data: {e}") from e

        digest = hashlib.sha256(decoded_key_data).digest()
        fingerprint_b64 = base64.b64encode(digest).decode("utf-8").rstrip("=")

        # Prefix follows the standard format
        return f"SHA256:{fingerprint_b64}"

    raise ValueError("Invalid SSH key format")


async def number_of_release_files(release: sql.Release) -> int:
    """Return the number of files in a release."""
    if (path := release_directory_revision(release)) is None:
        return 0
    count = 0
    async for _ in paths_recursive(path):
        count += 1
    return count


def parse_key_blocks(keys_text: str) -> list[str]:
    """Extract OpenPGP key blocks from a KEYS file."""
    key_blocks = []
    current_block = []
    in_key_block = False

    for line in keys_text.splitlines():
        if line.strip() == "-----BEGIN PGP PUBLIC KEY BLOCK-----":
            in_key_block = True
            current_block = [line]
        elif (line.strip() == "-----END PGP PUBLIC KEY BLOCK-----") and in_key_block:
            current_block.append(line)
            key_blocks.append("\n".join(current_block))
            in_key_block = False
        elif in_key_block:
            current_block.append(line)

    return key_blocks


def parse_key_blocks_bytes(keys_data: bytes) -> list[str]:
    """Extract OpenPGP key blocks from a KEYS file."""
    key_blocks = []
    current_block = []
    in_key_block = False

    for line in keys_data.splitlines():
        if line.strip() == b"-----BEGIN PGP PUBLIC KEY BLOCK-----":
            in_key_block = True
            current_block = [line]
        elif (line.strip() == b"-----END PGP PUBLIC KEY BLOCK-----") and in_key_block:
            current_block.append(line)
            key_blocks.append(b"\n".join(current_block))
            in_key_block = False
        elif in_key_block:
            current_block.append(line)

    return key_blocks


async def paths_recursive(base_path: pathlib.Path) -> AsyncGenerator[pathlib.Path]:
    """Yield all file paths recursively within a base path, relative to the base path."""
    if (resolved_base_path := await is_dir_resolve(base_path)) is None:
        return
    async for rel_path in paths_recursive_all(base_path):
        abs_path_to_check = resolved_base_path / rel_path
        with contextlib.suppress(FileNotFoundError, OSError):
            if await aiofiles.os.path.isfile(abs_path_to_check):
                yield rel_path


async def paths_recursive_all(base_path: pathlib.Path) -> AsyncGenerator[pathlib.Path]:
    """Yield all file and directory paths recursively within a base path, relative to the base path."""
    if (resolved_base_path := await is_dir_resolve(base_path)) is None:
        return
    queue: list[pathlib.Path] = [resolved_base_path]
    visited_abs_paths: set[pathlib.Path] = set()
    while queue:
        current_abs_item = queue.pop(0)
        try:
            resolved_current_abs_item = await asyncio.to_thread(current_abs_item.resolve)
        except (FileNotFoundError, OSError):
            continue
        if resolved_current_abs_item in visited_abs_paths:
            continue
        visited_abs_paths.add(resolved_current_abs_item)
        with contextlib.suppress(FileNotFoundError, OSError):
            for entry in await aiofiles.os.scandir(current_abs_item):
                entry_abs_path = pathlib.Path(entry.path)
                relative_path = entry_abs_path.relative_to(resolved_base_path)
                yield relative_path
                if entry.is_dir():
                    queue.append(entry_abs_path)


def permitted_announce_recipients(asf_uid: str) -> list[str]:
    return [
        # f"dev@{committee.name}.apache.org",
        # f"private@{committee.name}.apache.org",
        USER_TESTS_ADDRESS,
        f"{asf_uid}@apache.org",
    ]


def permitted_voting_recipients(asf_uid: str, committee_name: str) -> list[str]:
    return [
        f"dev@{committee_name}.apache.org",
        f"private@{committee_name}.apache.org",
        USER_TESTS_ADDRESS,
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


def release_directory(release: sql.Release) -> pathlib.Path:
    """Return the absolute path to the directory containing the active files for a given release phase."""
    latest_revision_number = release.latest_revision_number
    if (release.phase == sql.ReleasePhase.RELEASE) or (latest_revision_number is None):
        return release_directory_base(release)
    return release_directory_base(release) / latest_revision_number


def release_directory_base(release: sql.Release) -> pathlib.Path:
    """Determine the filesystem directory for a given release based on its phase."""
    phase = release.phase
    project_name = release.project.name
    version_name = release.version

    base_dir: pathlib.Path | None = None
    match phase:
        case sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
            base_dir = get_unfinished_dir()
        case sql.ReleasePhase.RELEASE_CANDIDATE:
            base_dir = get_unfinished_dir()
        case sql.ReleasePhase.RELEASE_PREVIEW:
            base_dir = get_unfinished_dir()
        case sql.ReleasePhase.RELEASE:
            base_dir = get_finished_dir()
        # Do not add "case _" here
    return base_dir / project_name / version_name


# def release_directory_eventual(release: models.Release) -> pathlib.Path:
#     """Return the path to the eventual destination of the release files."""
#     path_project = release.project.name
#     path_version = release.version
#     return get_finished_dir() / path_project / path_version


def release_directory_revision(release: sql.Release) -> pathlib.Path | None:
    """Return the path to the directory containing the active files for a given release phase."""
    path_project = release.project.name
    path_version = release.version
    match release.phase:
        case (
            sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
            | sql.ReleasePhase.RELEASE_CANDIDATE
            | sql.ReleasePhase.RELEASE_PREVIEW
        ):
            if (path_revision := release.latest_revision_number) is None:
                return None
            path = get_unfinished_dir() / path_project / path_version / path_revision
        case sql.ReleasePhase.RELEASE:
            path = get_finished_dir() / path_project / path_version
        # Do not add "case _" here
    return path


def release_directory_version(release: sql.Release) -> pathlib.Path:
    """Return the path to the directory containing the active files for a given release phase."""
    path_project = release.project.name
    path_version = release.version
    match release.phase:
        case (
            sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
            | sql.ReleasePhase.RELEASE_CANDIDATE
            | sql.ReleasePhase.RELEASE_PREVIEW
        ):
            path = get_unfinished_dir() / path_project / path_version
        case sql.ReleasePhase.RELEASE:
            path = get_finished_dir() / path_project / path_version
        # Do not add "case _" here
    return path


async def session_cache_read() -> dict[str, dict]:
    cache_path = pathlib.Path(config.get().STATE_DIR) / "user_session_cache.json"
    try:
        async with aiofiles.open(cache_path) as f:
            content = await f.read()
            return json.loads(content)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}


async def session_cache_write(cache_data: dict[str, dict]) -> None:
    cache_path = pathlib.Path(config.get().STATE_DIR) / "user_session_cache.json"

    cache_dir = cache_path.parent
    await asyncio.to_thread(os.makedirs, cache_dir, exist_ok=True)

    # Use the same pattern as update_atomic_symlink for the temporary file name
    temp_path = cache_dir / f".{cache_path.name}.{uuid.uuid4()}.tmp"

    try:
        async with aiofiles.open(temp_path, "w") as f:
            await f.write(json.dumps(cache_data, indent=2))
            await f.flush()
            await asyncio.to_thread(os.fsync, f.fileno())

        await aiofiles.os.rename(temp_path, cache_path)
    except Exception:
        try:
            await aiofiles.os.remove(temp_path)
        except FileNotFoundError:
            pass
        raise


def static_path(*args: str) -> str:
    filename = str(pathlib.PurePosixPath(*args))
    return quart.url_for("static", filename=filename)


def static_url(filename: str) -> str:
    """Return the URL for a static file."""
    return quart.url_for("static", filename=filename)


async def task_archive_url(task_mid: str) -> str | None:
    if "@" not in task_mid:
        return None

    # TODO: This List ID will be dynamic when we allow posting to arbitrary lists
    # lid = "user-tests.tooling.apache.org"
    lid = USER_TESTS_ADDRESS.replace("@", ".")
    url = f"https://lists.apache.org/api/email.lua?id=%3C{task_mid}%3E&listid=%3C{lid}%3E"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                response.raise_for_status()
                # TODO: Check whether this blocks from network
                email_data = await response.json()
        mid = email_data["mid"]
        if not isinstance(mid, str):
            return None
        return "https://lists.apache.org/thread/" + mid
    except Exception:
        log.exception("Failed to get archive URL for task %s", task_mid)
        return None


async def thread_messages(
    thread_id: str,
) -> AsyncGenerator[tuple[str, dict[str, Any]]]:
    """Iterate over mailing list thread messages in chronological order."""

    thread_url = f"https://lists.apache.org/api/thread.lua?id={thread_id}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(thread_url) as resp:
                resp.raise_for_status()
                thread_data: Any = await resp.json(content_type=None)
    except Exception as exc:
        raise FetchError(f"Failed fetching thread metadata for {thread_id}: {exc}") from exc

    message_ids: set[str] = set()

    if isinstance(thread_data, dict):
        for email_entry in thread_data.get("emails", []):
            if isinstance(email_entry, dict) and (mid := email_entry.get("id")):
                message_ids.add(str(mid))
        _thread_messages_walk(thread_data.get("thread"), message_ids)

    if not message_ids:
        return

    email_urls = [f"https://lists.apache.org/api/email.lua?id={mid}" for mid in message_ids]

    messages: list[dict[str, Any]] = []

    async for url, status, content in get_urls_as_completed(email_urls):
        if status != 200 or not content:
            log.warning("Failed to fetch email data from %s: %s", url, status)
            continue
        try:
            msg_json = json.loads(content.decode())
            messages.append(msg_json)
        except Exception as exc:
            log.warning("Failed to parse email JSON from %s: %s", url, exc)

    messages.sort(key=lambda m: m.get("epoch", 0))

    for msg_json in messages:
        msg_id = str(msg_json.get("id", ""))
        yield msg_id, msg_json


def unwrap[T](value: T | None, error_message: str = "unexpected None when unwrapping value") -> T:
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


def unwrap_type(value: T | None, t: type[T], error_message: str = "unexpected None when unwrapping value") -> T:
    """
    Will unwrap the given value or raise a TypeError if it is not of the expected type

    :param value: the optional value to unwrap
    :param t: the expected type of the value
    :param error_message: the error message when failing to unwrap
    """
    if value is None:
        raise ValueError(error_message)
    if not isinstance(value, t):
        raise ValueError(f"Expected {t}, got {type(value)}")
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
        log.info(f"Atomically updated symlink {link_path} -> {target_str}")
    except Exception as e:
        # Don't bother with log.exception here
        log.error(f"Failed to update atomic symlink {link_path} -> {target_str}: {e}")
        # Clean up temporary link if rename failed
        try:
            await aiofiles.os.remove(temp_link_path)
        except FileNotFoundError:
            # TODO: Use with contextlib.suppress(FileNotFoundError) for these sorts of blocks?
            pass
        raise


def user_releases(asf_uid: str, releases: Sequence[sql.Release]) -> list[sql.Release]:
    """Return a list of releases for which the user is a committee member or committer."""
    # TODO: This should probably be a session method instead
    user_releases = []
    for release in releases:
        if release.committee is None:
            continue
        if (asf_uid in release.committee.committee_members) or (asf_uid in release.committee.committers):
            user_releases.append(release)
    return user_releases


def validate_as_type[T](value: Any, t: type[T]) -> T:
    """Validate the given value as the given type."""
    if not isinstance(value, t):
        raise ValueError(f"Expected {t}, got {type(value)}")
    return value


async def validate_empty_form() -> None:
    empty_form = await forms.Empty.create_form(data=await quart.request.form)
    if not await empty_form.validate_on_submit():
        raise base.ASFQuartException("Invalid form submission. Please check your input and try again.", errorcode=400)


def validate_vote_duration(form: wtforms.Form, field: wtforms.IntegerField) -> None:
    """Checks if the value is 0 or between 72 and 144."""
    if field.data is None:
        # TODO: Check that this is what we intend
        return
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


async def _create_hard_link_clone_checks(
    source_dir: pathlib.Path,
    dest_dir: pathlib.Path,
    do_not_create_dest_dir: bool = False,
    exist_ok: bool = False,
    dry_run: bool = False,
) -> None:
    if dry_run and ((not do_not_create_dest_dir) or (not exist_ok)):
        raise ValueError("Cannot dry run and create destination directory or exist ok")

    # Ensure source exists and is a directory
    if (not dry_run) and (not await aiofiles.os.path.isdir(source_dir)):
        raise ValueError(f"Source path is not a directory or does not exist: {source_dir}")

    # Create destination directory
    if do_not_create_dest_dir is False:
        await aiofiles.os.makedirs(dest_dir, exist_ok=exist_ok)


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


def _thread_messages_walk(node: dict[str, Any] | None, message_ids: set[str]) -> None:
    if not isinstance(node, dict):
        return
    if mid := node.get("id"):
        message_ids.add(str(mid))
    for child in node.get("children", []):
        _thread_messages_walk(child, message_ids)
