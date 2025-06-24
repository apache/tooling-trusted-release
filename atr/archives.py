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

import logging
import os
import os.path
import tarfile
import zipfile
from typing import Final

import atr.tarzip as tarzip

_LOGGER: Final = logging.getLogger(__name__)


class ExtractionError(Exception):
    pass


def extract(
    archive_path: str,
    extract_dir: str,
    max_size: int,
    chunk_size: int,
    track_files: bool | set[str] = False,
) -> tuple[int, list[str]]:
    _LOGGER.info(f"Extracting {archive_path} to {extract_dir}")

    total_extracted = 0
    extracted_paths = []

    try:
        with tarzip.open_archive(archive_path) as archive:
            match archive.specific():
                case tarfile.TarFile() as tf:
                    for member in tf:
                        total_extracted, extracted_paths = _archive_extract_member(
                            tf, member, extract_dir, total_extracted, max_size, chunk_size, track_files, extracted_paths
                        )

                case zipfile.ZipFile():
                    for member in archive:
                        if not isinstance(member, tarzip.ZipMember):
                            continue
                        total_extracted, extracted_paths = _zip_archive_extract_member(
                            archive,
                            member,
                            extract_dir,
                            total_extracted,
                            max_size,
                            chunk_size,
                            track_files,
                            extracted_paths,
                        )

    except (tarfile.TarError, zipfile.BadZipFile, ValueError) as e:
        raise ExtractionError(f"Failed to read archive: {e}", {"archive_path": archive_path}) from e

    return total_extracted, extracted_paths


def total_size(tgz_path: str, chunk_size: int = 4096) -> int:
    with tarzip.open_archive(tgz_path) as archive:
        match archive.specific():
            case tarfile.TarFile() as tf:
                total_size = _size_tar(tf, chunk_size)

            case zipfile.ZipFile():
                total_size = _size_zip(archive, chunk_size)

    return total_size


def _archive_extract_safe_process_file(
    tf: tarfile.TarFile,
    member: tarfile.TarInfo,
    extract_dir: str,
    total_extracted: int,
    max_size: int,
    chunk_size: int,
) -> int:
    """Process a single file member during safe archive extraction."""
    target_path = os.path.join(extract_dir, member.name)
    if not os.path.abspath(target_path).startswith(os.path.abspath(extract_dir)):
        _LOGGER.warning(f"Skipping potentially unsafe path: {member.name}")
        return 0

    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    source = tf.extractfile(member)
    if source is None:
        # Should not happen if member.isreg() is true
        _LOGGER.warning(f"Could not extract file object for member: {member.name}")
        return 0

    extracted_file_size = 0
    try:
        with open(target_path, "wb") as target:
            while chunk := source.read(chunk_size):
                target.write(chunk)
                extracted_file_size += len(chunk)

                # Check size limits during extraction
                if (total_extracted + extracted_file_size) > max_size:
                    # Clean up the partial file before raising
                    target.close()
                    os.unlink(target_path)
                    raise ExtractionError(
                        f"Extraction exceeded maximum size limit of {max_size} bytes",
                        {"max_size": max_size, "current_size": total_extracted},
                    )
    finally:
        source.close()

    return extracted_file_size


def _archive_extract_member(
    tf: tarfile.TarFile,
    member: tarfile.TarInfo,
    extract_dir: str,
    total_extracted: int,
    max_size: int,
    chunk_size: int,
    track_files: bool | set[str] = False,
    extracted_paths: list[str] = [],
) -> tuple[int, list[str]]:
    member_basename = os.path.basename(member.name)
    if member_basename.startswith("._"):
        # Metadata convention
        return 0, extracted_paths

    # Skip any character device, block device, or FIFO
    if member.isdev():
        return 0, extracted_paths

    if track_files and isinstance(track_files, set) and (member_basename in track_files):
        extracted_paths.append(member.name)

    # Check whether extraction would exceed the size limit
    if member.isreg() and ((total_extracted + member.size) > max_size):
        raise ExtractionError(
            f"Extraction would exceed maximum size limit of {max_size} bytes",
            {"max_size": max_size, "current_size": total_extracted, "file_size": member.size},
        )

    # Extract directories directly
    if member.isdir():
        # Ensure the path is safe before extracting
        target_path = os.path.join(extract_dir, member.name)
        if not os.path.abspath(target_path).startswith(os.path.abspath(extract_dir)):
            _LOGGER.warning(f"Skipping potentially unsafe path: {member.name}")
            return 0, extracted_paths
        tf.extract(member, extract_dir, numeric_owner=True)

    elif member.isreg():
        extracted_size = _archive_extract_safe_process_file(
            tf, member, extract_dir, total_extracted, max_size, chunk_size
        )
        total_extracted += extracted_size

    elif member.issym():
        _archive_extract_safe_process_symlink(member, extract_dir)

    elif member.islnk():
        _archive_extract_safe_process_hardlink(member, extract_dir)

    return total_extracted, extracted_paths


def _archive_extract_safe_process_hardlink(member: tarfile.TarInfo, extract_dir: str) -> None:
    """Safely create a hard link from the TarInfo entry."""
    target_path = _safe_path(extract_dir, member.name)
    if target_path is None:
        _LOGGER.warning(f"Skipping potentially unsafe hard link path: {member.name}")
        return

    link_target = member.linkname or ""
    source_path = _safe_path(extract_dir, link_target)
    if source_path is None or not os.path.exists(source_path):
        _LOGGER.warning(f"Skipping hard link with invalid target: {member.name} -> {link_target}")
        return

    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    try:
        if os.path.lexists(target_path):
            return
        os.link(source_path, target_path)
    except (OSError, NotImplementedError) as e:
        _LOGGER.warning(f"Failed to create hard link {target_path} -> {source_path}: {e}")


def _archive_extract_safe_process_symlink(member: tarfile.TarInfo, extract_dir: str) -> None:
    """Safely create a symbolic link from the TarInfo entry."""
    target_path = _safe_path(extract_dir, member.name)
    if target_path is None:
        _LOGGER.warning(f"Skipping potentially unsafe symlink path: {member.name}")
        return

    link_target = member.linkname or ""

    # Reject absolute targets to avoid links outside the tree
    if os.path.isabs(link_target):
        _LOGGER.warning(f"Skipping symlink with absolute target: {member.name} -> {link_target}")
        return

    # Ensure that the resolved link target stays within the extraction directory
    resolved_target = _safe_path(os.path.dirname(target_path), link_target)
    if resolved_target is None:
        _LOGGER.warning(f"Skipping symlink pointing outside tree: {member.name} -> {link_target}")
        return

    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    try:
        if os.path.lexists(target_path):
            return
        os.symlink(link_target, target_path)
    except (OSError, NotImplementedError) as e:
        _LOGGER.warning("Failed to create symlink %s -> %s: %s", target_path, link_target, e)


def _safe_path(base_dir: str, *paths: str) -> str | None:
    """Return an absolute path within the base_dir built from the given paths, or None if it escapes."""
    target = os.path.abspath(os.path.join(base_dir, *paths))
    if target.startswith(os.path.abspath(base_dir)):
        return target
    return None


def _size_tar(tf: tarfile.TarFile, chunk_size: int) -> int:
    total_size = 0
    for member in tf:
        total_size += member.size
        if member.isfile():
            fileobj = tf.extractfile(member)
            if fileobj is not None:
                while fileobj.read(chunk_size):
                    pass
    return total_size


def _size_zip(archive: tarzip.Archive, chunk_size: int) -> int:
    total_size = 0
    for member in archive:
        if not isinstance(member, tarzip.ZipMember):
            continue
        total_size += member.size
        if member.isfile():
            fileobj = archive.extractfile(member)
            if fileobj is not None:
                while fileobj.read(chunk_size):
                    pass
    return total_size


def _zip_archive_extract_member(
    archive: tarzip.Archive,
    member: tarzip.ZipMember,
    extract_dir: str,
    total_extracted: int,
    max_size: int,
    chunk_size: int,
    track_files: bool | set[str] = False,
    extracted_paths: list[str] = [],
) -> tuple[int, list[str]]:
    member_basename = os.path.basename(member.name)
    if track_files and (isinstance(track_files, set) and (member_basename in track_files)):
        extracted_paths.append(member.name)

    if member_basename.startswith("._"):
        return 0, extracted_paths

    if member.isfile() and (total_extracted + member.size) > max_size:
        raise ExtractionError(
            f"Extraction would exceed maximum size limit of {max_size} bytes",
            {"max_size": max_size, "current_size": total_extracted, "file_size": member.size},
        )

    if member.isdir():
        target_path = os.path.join(extract_dir, member.name)
        if not os.path.abspath(target_path).startswith(os.path.abspath(extract_dir)):
            _LOGGER.warning("Skipping potentially unsafe path: %s", member.name)
            return 0, extracted_paths
        os.makedirs(target_path, exist_ok=True)
        return total_extracted, extracted_paths

    if member.isfile():
        extracted_size = _zip_extract_safe_process_file(
            archive, member, extract_dir, total_extracted, max_size, chunk_size
        )
        return total_extracted + extracted_size, extracted_paths

    return total_extracted, extracted_paths


def _zip_extract_safe_process_file(
    archive: tarzip.Archive,
    member: tarzip.ZipMember,
    extract_dir: str,
    total_extracted: int,
    max_size: int,
    chunk_size: int,
) -> int:
    target_path = os.path.join(extract_dir, member.name)
    if not os.path.abspath(target_path).startswith(os.path.abspath(extract_dir)):
        _LOGGER.warning(f"Skipping potentially unsafe path: {member.name}")
        return 0

    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    source = archive.extractfile(member)
    if source is None:
        _LOGGER.warning(f"Could not extract {member.name} from archive")
        return 0

    extracted_file_size = 0
    try:
        with open(target_path, "wb") as target:
            while chunk := source.read(chunk_size):
                target.write(chunk)
                extracted_file_size += len(chunk)

                if (total_extracted + extracted_file_size) > max_size:
                    target.close()
                    os.unlink(target_path)
                    raise ExtractionError(
                        f"Extraction exceeded maximum size limit of {max_size} bytes",
                        {"max_size": max_size, "current_size": total_extracted},
                    )
    finally:
        source.close()

    return extracted_file_size
