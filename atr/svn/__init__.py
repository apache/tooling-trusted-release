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
import datetime
import pathlib
from typing import Final, Self

import pydantic
import pydantic_xml

import atr.config as config
import atr.log as log

_ASF_TOOL: Final[str] = "atr"


class CommandExecutionError(RuntimeError):
    # TODO: These are never assigned
    returncode: int
    output: str


class SvnInfo(pydantic.BaseModel):
    """A dataclass to hold information about a file in a subversion repository."""

    path: str
    name: str
    url: str
    relative_url: str
    repository_root: str
    revision: str
    last_changed_author: str
    last_changed_rev: str
    last_changed_date: str
    checksum: str | None = None
    text_last_updated: str | None = None

    @property
    def revision_number(self) -> int:
        return int(self.revision)

    @property
    def last_changed_rev_number(self) -> int:
        return int(self.last_changed_rev)

    @classmethod
    async def from_url(cls, url: str) -> Self:
        output = await _run_svn_info(url)

        nfo = {}
        for line in output.split("\n"):
            # TODO: Might break on IPv6 hosts, or hosts with a port?
            k, v = line.split(":", 1)
            nfo[k.replace(" ", "_").lower()] = v.strip()

        return cls.model_validate(nfo)

    @classmethod
    async def from_path(cls, path: pathlib.Path) -> Self:
        return await cls.from_url(str(path))


class SvnLogEntry(pydantic_xml.BaseXmlModel):
    revision: int = pydantic_xml.attr()
    author: str = pydantic_xml.element()
    date: str = pydantic_xml.element()
    msg: str | None = pydantic_xml.element(default=None)

    @property
    def datetime(self) -> datetime.datetime:
        return datetime.datetime.fromisoformat(self.date)


class SvnLog(pydantic_xml.BaseXmlModel, tag="log"):
    entries: list[SvnLogEntry] = pydantic_xml.element(tag="logentry")


async def _run_svnmucc_command(*args: str) -> str:
    return await run_command("svnmucc", *args)


async def _run_svn_command(sub_cmd: str, path: str, *args: str) -> str:
    # Do not log this command, as it may contain a password or secret token
    return await run_command("svn", *[sub_cmd, *args, path])


async def _run_svn_info(path_or_url: str) -> str:
    log.debug(f"fetching svn info for '{path_or_url}'")
    return await _run_svn_command("info", path_or_url)


async def update(path: pathlib.Path) -> str:
    log.debug(f"running svn update for '{path}'")
    return await _run_svn_command("update", str(path), "--parents")


async def get_log(path: pathlib.Path) -> SvnLog:
    log.debug(f"running svn log for '{path}'")
    svn_token = config.get().SVN_TOKEN
    if svn_token is None:
        raise ValueError("SVN_TOKEN must be set")
    # TODO: Or omit username entirely?
    log_output = await _run_svn_command("log", str(path), "--xml", "--username", _ASF_TOOL, "--password", svn_token)
    return SvnLog.from_xml(log_output)


async def get_diff(path: pathlib.Path, revision: int) -> str:
    log.debug(f"running svn diff for '{path}': r{revision}")
    svn_token = config.get().SVN_TOKEN
    if svn_token is None:
        raise ValueError("SVN_TOKEN must be set")
    # TODO: Or omit username entirely?
    return await _run_svn_command(
        "diff", str(path), "-c", str(revision), "--username", _ASF_TOOL, "--password", svn_token
    )


async def commit(path: pathlib.Path, url: str, username: str, revision: str, message: str) -> str:
    log.debug(f"running svn commit for user '{username}' to '{url}'")
    # The username here is the ASF UID of the committer
    svn_token = config.get().SVN_TOKEN
    if svn_token is None:
        raise ValueError("SVN_TOKEN must be set")
    return await _run_svnmucc_command(
        "put",
        str(path),
        url,
        "--username",
        username,
        "--password",
        svn_token,
        "--non-interactive",
        "--with-revprop",
        f"asf:tool={_ASF_TOOL}",
        "-r",
        revision,
        "-m",
        message,
    )


async def run_command(cmd: str, *args: str) -> str:
    """Run a svn command asynchronously.

    Arguments:
        cmd (str): the command to run
        *args (str): arguments to pass to the command
    """
    proc = await asyncio.create_subprocess_exec(
        cmd,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await proc.communicate()

    # if the proc.communicate() call returns an error
    # print the error out and return an empty string.
    if proc.returncode:
        raise CommandExecutionError(proc.returncode, stderr.decode())
    else:
        output = stdout.decode().strip()
        return output
