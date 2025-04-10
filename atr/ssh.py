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
from typing import Final, TypeVar

import aiofiles
import aiofiles.os
import asyncssh

import atr.config as config
import atr.db as db
import atr.db.models as models
import atr.revision as revision
import atr.user as user
import atr.util as util

_LOGGER: Final = logging.getLogger(__name__)
_CONFIG: Final = config.get()

T = TypeVar("T")


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


def _command_simple_validate(argv: list[str]) -> tuple[str | None, int]:
    if argv[0] != "rsync":
        return "The first argument should be rsync", -1

    if argv[1] != "--server":
        return "The second argument should be --server", -1

    # TODO: Might need to accept permutations of this
    # Also certain versions of rsync might change the options
    acceptable_options: Final[str] = "vlogDtpre"
    if not argv[2].startswith(f"-{acceptable_options}."):
        return f"The third argument should start with -{acceptable_options}.", -1

    if not argv[2][len(f"-{acceptable_options}.") :].isalpha():
        return "The third argument should be a valid command", -1

    # Support --delete as an optional argument before the path
    if argv[3] != "--delete":
        # No --delete, short command
        if argv[3] != ".":
            return "The fourth argument should be .", -1
        if len(argv) != 5:
            return "There should be 5 arguments", -1
        path_index = 4
    else:
        # Has --delete, long command
        if argv[4] != ".":
            return "The fifth argument should be .", -1
        if len(argv) != 6:
            return "There should be 6 arguments", -1
        path_index = 5

    return None, path_index


async def _command_validate(
    process: asyncssh.SSHServerProcess, argv: list[str], path_index: int
) -> tuple[str, str] | None:
    result = _command_path_validate(argv[path_index])
    if isinstance(result, str):
        _fail(process, result, None)
        return None
    path_project, path_version = result

    # Ensure that the user has permission to upload to this project
    async with db.session() as data:
        project = await data.project(name=path_project, _committee=True).get()
        if not project:
            # Projects are public, so existence information is public
            _fail(process, "This project does not exist", None)
            return None
        release = await data.release(project_id=project.id, version=path_version).get()
        # The SSH UID has also been validated by SSH as being the ASF UID
        # Since users can only set an SSH key when authenticated using ASF OAuth
        ssh_uid = process.get_extra_info("username")
        if not release:
            # The user is requesting to create a new release
            # Check whether the user has permission to create a release for this project
            if not user.is_committee_member(project.committee, ssh_uid):
                _fail(process, "You must be a member of this project's committee to create a release", None)
                return None
        else:
            # The user is requesting to upload to an existing release
            # Check whether the user has permission to upload to this release
            if not user.is_committer(release.committee, ssh_uid):
                _fail(
                    process,
                    "You must be a member of this project's committee or a committer to upload to this release",
                    None,
                )
                return None
    return path_project, path_version


async def _ensure_release_object(process: asyncssh.SSHServerProcess, project_name: str, version_name: str) -> bool:
    try:
        async with db.session() as data:
            async with data.begin():
                release = await data.release(
                    name=models.release_name(project_name, version_name), _committee=True
                ).get()
                if release is None:
                    project = await data.project(name=project_name, _committee=True).demand(
                        RuntimeError("Project not found")
                    )
                    if version_name_error := util.version_name_error(version_name):
                        raise RuntimeError(f'Invalid version name "{version_name}": {version_name_error}')
                    # Create a new release object
                    release = models.Release(
                        project_id=project.id,
                        project=project,
                        version=version_name,
                        stage=models.ReleaseStage.RELEASE_CANDIDATE,
                        phase=models.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
                        created=datetime.datetime.now(datetime.UTC),
                    )
                    data.add(release)
                elif release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
                    return _fail(
                        process, f"Release {release.name} is no longer in draft phase ({release.phase.value})", False
                    )
        return True
    except Exception as e:
        _LOGGER.exception("Error creating release object")
        return _fail(process, f"Internal error creating release object: {e}", False)


async def _execute_rsync(process: asyncssh.SSHServerProcess, argv: list[str]) -> int:
    _LOGGER.info(f"Executing modified command: {' '.join(argv)}")
    proc = await asyncio.create_subprocess_shell(
        " ".join(argv),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await process.redirect(stdin=proc.stdin, stdout=proc.stdout, stderr=proc.stderr)
    exit_status = await proc.wait()
    return exit_status


def _fail(proc: asyncssh.SSHServerProcess, message: str, return_value: T) -> T:
    _LOGGER.error(message)
    proc.stderr.write(f"ATR SSH error: {message}\n".encode())
    proc.exit(1)
    return return_value


async def _process_validated_rsync(
    process: asyncssh.SSHServerProcess,
    argv: list[str],
    path_index: int,
    project_name: str,
    version_name: str,
) -> None:
    asf_uid = process.get_extra_info("username")
    exit_status = 1

    try:
        async with revision.create_and_manage(project_name, version_name, asf_uid) as (
            new_revision_dir,
            new_draft_revision,
        ):
            # Update the rsync command path to the new revision directory
            # The revision directory has already been created by the context manager
            argv[path_index] = str(new_revision_dir)

            # Ensure that the release object exists
            # This performs validation, so must be done before the rsync command
            if not await _ensure_release_object(process, project_name, version_name):
                process.exit(1)
                return

            # Execute the rsync command
            exit_status = await _execute_rsync(process, argv)
            if exit_status != 0:
                _LOGGER.error(
                    f"rsync failed with exit status {exit_status} for revision {new_draft_revision}. \
                    Command: {process.command} (run as {' '.join(argv)})"
                )
                process.exit(exit_status)
                return

            # Exit with the rsync exit status
            process.exit(exit_status)

    except Exception as e:
        _LOGGER.exception(f"Error during draft revision processing for {project_name}-{version_name}")
        _fail(process, f"Internal error processing revision: {e}", None)
        if not process.is_closing():
            process.exit(1)


async def _handle_client(process: asyncssh.SSHServerProcess) -> None:
    """Process client command by executing it and redirecting I/O."""
    asf_uid = process.get_extra_info("username")
    _LOGGER.info(f"Handling command for authenticated user: {asf_uid}")

    if not process.command:
        process.stderr.write(b"ATR SSH error: No command specified\n")
        process.exit(1)
        return

    _LOGGER.info(f"Command received: {process.command}")
    argv = process.command.split()

    simple_validation_error, path_index = _command_simple_validate(argv)
    if simple_validation_error:
        process.stderr.write(f"ATR SSH error: {simple_validation_error}\nCommand: {process.command}\n".encode())
        process.exit(1)
        return

    validation_results = await _command_validate(process, argv, path_index)
    if not validation_results:
        return
    project_name, version_name = validation_results

    await _process_validated_rsync(process, argv, path_index, project_name, version_name)
