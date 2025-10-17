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

import contextlib
import tarfile
import zipfile
from collections.abc import Generator, Iterator
from typing import IO, TypeVar
from typing import Protocol as TypingProtocol

ArchiveT = TypeVar("ArchiveT", tarfile.TarFile, zipfile.ZipFile)
# If you set this covariant=True, then mypy says an "invariant one is expected"
# But pyright warns, "should be covariant" if you don't
# We'll use the covariant version and ignore the mypy error
MemberT = TypeVar("MemberT", tarfile.TarInfo, zipfile.ZipInfo, covariant=True)


class AbstractArchiveMember[MemberT: (tarfile.TarInfo, zipfile.ZipInfo)](TypingProtocol):  # type: ignore[misc]
    name: str
    size: int
    linkname: str | None

    _original_info: MemberT

    def isfile(self) -> bool: ...
    def isdir(self) -> bool: ...
    def issym(self) -> bool: ...
    def islnk(self) -> bool: ...
    def isdev(self) -> bool: ...


class TarMember(AbstractArchiveMember[tarfile.TarInfo]):
    def __init__(self, original: tarfile.TarInfo):
        self.name = original.name
        self._original_info = original
        self.size = original.size
        self.linkname = original.linkname if hasattr(original, "linkname") else None

    def isfile(self) -> bool:
        return self._original_info.isfile()

    def isdir(self) -> bool:
        return self._original_info.isdir()

    def issym(self) -> bool:
        return self._original_info.issym()

    def islnk(self) -> bool:
        return self._original_info.islnk()

    def isdev(self) -> bool:
        return self._original_info.isdev()


class ZipMember(AbstractArchiveMember[zipfile.ZipInfo]):
    def __init__(self, original: zipfile.ZipInfo):
        self.name = original.filename
        self._original_info = original

        self.size = original.file_size
        # Link targets are not encoded in ZIP files
        self.linkname: str | None = None

    def isfile(self) -> bool:
        return not self._original_info.is_dir()

    def isdir(self) -> bool:
        return self._original_info.is_dir()

    def issym(self) -> bool:
        return False

    def islnk(self) -> bool:
        return False

    def isdev(self) -> bool:
        return False


type Member = TarMember | ZipMember


class ArchiveContext[ArchiveT: (tarfile.TarFile, zipfile.ZipFile)]:
    _archive_obj: ArchiveT

    def __init__(self, archive_obj: ArchiveT):
        self._archive_obj = archive_obj

    def __iter__(self) -> Iterator[TarMember | ZipMember]:
        match self._archive_obj:
            case tarfile.TarFile() as tf:
                for member_orig in tf:
                    if member_orig.isdev():
                        continue
                    yield TarMember(member_orig)
            case zipfile.ZipFile() as zf:
                for member_orig in zf.infolist():
                    yield ZipMember(member_orig)

    def extractfile(self, member_wrapper: Member) -> IO[bytes] | None:
        try:
            match self._archive_obj:
                case tarfile.TarFile() as tf:
                    if not isinstance(member_wrapper, TarMember):
                        raise TypeError("Archive is TarFile, but member_wrapper is not TarMember")
                    return tf.extractfile(member_wrapper._original_info)
                case zipfile.ZipFile() as zf:
                    if not isinstance(member_wrapper, ZipMember):
                        raise TypeError("Archive is ZipFile, but member_wrapper is not ZipMember")
                    return zf.open(member_wrapper._original_info)
        except (KeyError, AttributeError, Exception):
            return None

    def specific(self) -> tarfile.TarFile | zipfile.ZipFile:
        return self._archive_obj


type TarArchive = ArchiveContext[tarfile.TarFile]
type ZipArchive = ArchiveContext[zipfile.ZipFile]
type Archive = TarArchive | ZipArchive


@contextlib.contextmanager
def open_archive(archive_path: str) -> Generator[Archive]:
    archive_file: tarfile.TarFile | zipfile.ZipFile | None = None
    try:
        try:
            archive_file = tarfile.open(archive_path, "r:*")
        except tarfile.ReadError:
            try:
                archive_file = zipfile.ZipFile(archive_path, "r")
            except zipfile.BadZipFile:
                raise ValueError(f"Unsupported or corrupted archive: {archive_path}")

        match archive_file:
            case tarfile.TarFile() as tf_concrete:
                yield ArchiveContext[tarfile.TarFile](tf_concrete)
            case zipfile.ZipFile() as zf_concrete:
                yield ArchiveContext[zipfile.ZipFile](zf_concrete)

    finally:
        if archive_file:
            archive_file.close()
