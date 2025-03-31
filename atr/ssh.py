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

"""SSH server module for ATR."""

import asyncio
import asyncio.subprocess
import datetime
import logging
import os
import string
from typing import Final

import aiofiles
import aiofiles.os
import asyncssh

import atr.config as config
import atr.db as db
import atr.db.models as models
import atr.tasks.checks as checks
import atr.tasks.rsync as rsync
import atr.user as user
import atr.util as util

_LOGGER: Final = logging.getLogger(__name__)
_CONFIG: Final = config.get()


class _SSHServer(asyncssh.SSHServer):
    """Simple SSH server that handles connections."""

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        """Called when a connection is established."""
        # Store connection for use in begin_auth
        self._conn = conn
        peer_addr = conn.get_extra_info("peername")[0]
        _LOGGER.info(f"SSH connection received from {peer_addr}")

    def connection_lost(self, exc: Exception | None) -> None:
        """Called when a connection is lost or closed."""
        if exc:
            _LOGGER.error(f"SSH connection error: {exc}")
        else:
            _LOGGER.info("SSH connection closed")

    async def begin_auth(self, username: str) -> bool:
        """Begin authentication for the specified user."""
        _LOGGER.info(f"Beginning auth for user {username}")

        try:
            # Load SSH keys for this user from the database
            async with db.session() as data:
                user_keys = await data.ssh_key(asf_uid=username).all()

                if not user_keys:
                    _LOGGER.warning(f"No SSH keys found for user: {username}")
                    # Still require authentication, but it will fail
                    return True

                # Create an authorized_keys file as a string
                auth_keys_lines = []
                for user_key in user_keys:
                    auth_keys_lines.append(user_key.key)

                auth_keys_data = "\n".join(auth_keys_lines)
                _LOGGER.info(f"Loaded {len(user_keys)} SSH keys for user {username}")

                # Set the authorized keys in the connection
                try:
                    authorized_keys = asyncssh.import_authorized_keys(auth_keys_data)
                    self._conn.set_authorized_keys(authorized_keys)
                    _LOGGER.info(f"Successfully set authorized keys for {username}")
                except Exception as e:
                    _LOGGER.error(f"Error setting authorized keys: {e}")

        except Exception as e:
            _LOGGER.error(f"Database error loading SSH keys: {e}")

        # Always require authentication
        return True

    def public_key_auth_supported(self) -> bool:
        """Indicate whether public key authentication is supported."""
        return True


async def server_start() -> asyncssh.SSHAcceptor:
    """Start the SSH server."""
    # TODO: Where do we actually do this?
    # await aiofiles.os.makedirs(_CONFIG.STATE_DIR, exist_ok=True)

    # Generate temporary host key if it doesn't exist
    key_path = os.path.join(_CONFIG.STATE_DIR, "ssh_host_key")
    if not await aiofiles.os.path.exists(key_path):
        private_key = asyncssh.generate_private_key("ssh-rsa")
        private_key.write_private_key(key_path)
        _LOGGER.info(f"Generated SSH host key at {key_path}")

    server = await asyncssh.create_server(
        _SSHServer,
        server_host_keys=[key_path],
        process_factory=_handle_client,
        host=_CONFIG.SSH_HOST,
        port=_CONFIG.SSH_PORT,
        encoding=None,
    )

    _LOGGER.info(f"SSH server started on {_CONFIG.SSH_HOST}:{_CONFIG.SSH_PORT}")
    return server


async def server_stop(server: asyncssh.SSHAcceptor) -> None:
    """Stop the SSH server."""
    server.close()
    await server.wait_closed()
    _LOGGER.info("SSH server stopped")


def _command_path_validate(path: str) -> tuple[str, str] | str:
    if not path.startswith("/"):
        return "The fifth argument should be an absolute path"

    if not path.endswith("/"):
        # Technically we could ignore this, because we rewrite the path anyway
        # But we should enforce good rsync usage practices
        return "The fifth argument should be a directory path, ending with a /"

    if "//" in path:
        return "The fifth argument should not contain //"

    if path.count("/") != 3:
        return "The fifth argument should be a /PROJECT/VERSION/ directory path"

    path_project, path_version = path.strip("/").split("/", 1)
    alphanum = set(string.ascii_letters + string.digits)
    if not all(c in alphanum for c in path_project):
        return "The project name should contain only alphanumeric characters"

    # From a survey of version numbers we find that only . and - are used
    # We also allow + which is in common use
    version_punctuation = set(".-+")
    if path_version[0] not in alphanum:
        # Must certainly not allow the directory to be called "." or ".."
        # And we also want to avoid patterns like ".htaccess"
        return "The version should start with an alphanumeric character"
    if path_version[-1] not in alphanum:
        return "The version should end with an alphanumeric character"
    if not all(c in (alphanum | version_punctuation) for c in path_version):
        return "The version should contain only alphanumeric characters, dots, dashes, or pluses"

    return path_project, path_version


def _command_simple_validate(argv: list[str]) -> str | None:
    if argv[0] != "rsync":
        return "The first argument should be rsync"

    if argv[1] != "--server":
        return "The second argument should be --server"

    # TODO: Might need to accept permutations of this
    # Also certain versions of rsync might change the options
    acceptable_options: Final[str] = "vlogDtpre"
    if not argv[2].startswith(f"-{acceptable_options}."):
        return f"The third argument should start with -{acceptable_options}."

    if not argv[2][len(f"-{acceptable_options}.") :].isalpha():
        return "The third argument should be a valid command"

    # Support --delete as an optional argument before the path
    if argv[3] != "--delete":
        # No --delete, short command
        if argv[3] != ".":
            return "The fourth argument should be ."
        if len(argv) != 5:
            return "There should be 5 arguments"
    else:
        # Has --delete, long command
        if argv[4] != ".":
            return "The fifth argument should be ."
        if len(argv) != 6:
            return "There should be 6 arguments"

    return None


async def _command_validate(process: asyncssh.SSHServerProcess) -> tuple[str, str, list[str]] | None:
    def fail(message: str) -> tuple[str, str, list[str]] | None:
        # NOTE: Changing the return type to just None really confuses mypy
        _LOGGER.error(message)
        process.stderr.write(f"ATR SSH error: {message}\nCommand: {process.command}\n".encode())
        process.exit(1)
        return None

    command = process.command
    if not command:
        return fail("No command specified")

    _LOGGER.info(f"Command received: {command}")
    argv = command.split()

    error = _command_simple_validate(argv)
    if error:
        return fail(error)

    if argv[3] == "--delete":
        path_index = 5
    else:
        path_index = 4

    result = _command_path_validate(argv[path_index])
    if isinstance(result, str):
        return fail(result)
    path_project, path_version = result

    # Ensure that the user has permission to upload to this project
    async with db.session() as data:
        project = await data.project(name=path_project, _committee=True).get()
        if not project:
            # Projects are public, so existence information is public
            return fail("This project does not exist")
        release = await data.release(project_id=project.id, version=path_version).get()
        # The SSH UID has also been validated by SSH as being the ASF UID
        # Since users can only set an SSH key when authenticated using ASF OAuth
        ssh_uid = process.get_extra_info("username")
        if not release:
            # The user is requesting to create a new release
            # Check if the user has permission to create a release for this project
            if not user.is_committee_member(project.committee, ssh_uid):
                return fail("You must be a member of this project's committee to create a release")
        else:
            # The user is requesting to upload to an existing release
            # Check if the user has permission to upload to this release
            if not user.is_committer(release.committee, ssh_uid):
                return fail("You must be a member of this project's committee or a committer to upload to this release")

    # Set the target directory to the release storage directory
    argv[path_index] = str(util.get_release_candidate_draft_dir() / path_project / path_version)
    _LOGGER.info(f"Modified command: {argv}")

    # Create the release's storage directory if it doesn't exist
    await aiofiles.os.makedirs(argv[path_index], exist_ok=True)

    return path_project, path_version, argv


async def _handle_client(process: asyncssh.SSHServerProcess) -> None:
    """Process client command by executing it and redirecting I/O."""
    asf_uid = process.get_extra_info("username")
    _LOGGER.info(f"Handling command for authenticated user: {asf_uid}")

    validation_results = await _command_validate(process)
    if not validation_results:
        return
    project_name, release_version, argv = validation_results

    try:
        # Create subprocess to actually run the command
        # NOTE: asyncio base_events subprocess_shell requires cmd be str | bytes
        # Ought to be list[str] | list[bytes] really
        proc = await asyncio.create_subprocess_shell(
            " ".join(argv),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Redirect I/O between SSH process and the subprocess
        await process.redirect(stdin=proc.stdin, stdout=proc.stdout, stderr=proc.stderr)

        # Wait for the process to complete
        exit_status = await proc.wait()

        # Start a task to process the new files
        release_name = f"{project_name}-{release_version}"
        async with db.session() as data:
            release = await data.release(name=release_name, _committee=True).get()
            # Create the release if it does not already exist
            if release is None:
                project = await data.project(name=project_name, _committee=True).demand(
                    RuntimeError("Project not found")
                )
                release = models.Release(
                    name=release_name,
                    project_id=project.id,
                    project=project,
                    version=release_version,
                    stage=models.ReleaseStage.RELEASE_CANDIDATE,
                    phase=models.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
                    created=datetime.datetime.now(),
                )
                data.add(release)
                await data.commit()
            if release.stage != models.ReleaseStage.RELEASE_CANDIDATE:
                raise RuntimeError("Release is not in the candidate stage")
            if release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
                raise RuntimeError("Release is not in the candidate draft phase")

            # Add a task to analyse the new files
            data.add(
                models.Task(
                    status=models.TaskStatus.QUEUED,
                    task_type=checks.function_key(rsync.analyse),
                    task_args=rsync.Analyse(
                        project_name=project_name,
                        release_version=release_version,
                    ).model_dump(),
                )
            )
            await data.commit()

        # Exit the SSH process with the same status as the rsync process
        process.exit(exit_status)

    except Exception as e:
        _LOGGER.exception(f"Error executing command {process.command}")
        process.stderr.write(f"Error: {e!s}\n")
        process.exit(1)
