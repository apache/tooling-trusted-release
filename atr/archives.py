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
from typing import Final

_LOGGER: Final = logging.getLogger(__name__)


class ExtractionError(Exception):
    pass


def targz_extract(
    archive_path: str,
    extract_dir: str,
    max_size: int,
    chunk_size: int,
) -> int:
    """Safe archive extraction."""
    total_extracted = 0

    try:
        with tarfile.open(archive_path, mode="r|gz") as tf:
            for member in tf:
                keep_going, total_extracted = archive_extract_member(
                    tf, member, extract_dir, total_extracted, max_size, chunk_size
                )
                if not keep_going:
                    break

    except tarfile.ReadError as e:
        raise ExtractionError(f"Failed to read archive: {e}", {"archive_path": archive_path}) from e

    return total_extracted


def targz_total_size(tgz_path: str, chunk_size: int = 4096) -> int:
    """Verify a .tar.gz file and compute its uncompressed size."""
    total_size = 0

    with tarfile.open(tgz_path, mode="r|gz") as tf:
        for member in tf:
            # Do not skip metadata here
            total_size += member.size
            # Verify file by extraction
            if member.isfile():
                f = tf.extractfile(member)
                if f is not None:
                    while True:
                        data = f.read(chunk_size)
                        if not data:
                            break
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


def archive_extract_member(
    tf: tarfile.TarFile, member: tarfile.TarInfo, extract_dir: str, total_extracted: int, max_size: int, chunk_size: int
) -> tuple[bool, int]:
    if member.name and member.name.split("/")[-1].startswith("._"):
        # Metadata convention
        return False, 0

    # Skip any character device, block device, or FIFO
    if member.isdev():
        return False, 0

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
            return False, 0
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

    return True, total_extracted


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
