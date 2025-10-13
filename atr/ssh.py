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
import os
import string
import time
from typing import Final, TypeVar

import aiofiles
import aiofiles.os
import asyncssh

import atr.config as config
import atr.db as db
import atr.log as log
import atr.models.sql as sql
import atr.storage as storage
import atr.storage.types as types
import atr.user as user
import atr.util as util

_CONFIG: Final = config.get()

T = TypeVar("T")


class RsyncArgsError(Exception):
    """Exception raised when the rsync arguments are invalid."""

    pass


class SSHServer(asyncssh.SSHServer):
    """Simple SSH server that handles connections."""

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        """Called when a connection is established."""
        # Store connection for use in begin_auth
        self._conn = conn
        peer_addr = conn.get_extra_info("peername")[0]
        log.info(f"SSH connection received from {peer_addr}")

    def connection_lost(self, exc: Exception | None) -> None:
        """Called when a connection is lost or closed."""
        if exc:
            log.error(f"SSH connection error: {exc}")
        else:
            log.info("SSH connection closed")

    async def begin_auth(self, username: str) -> bool:
        """Begin authentication for the specified user."""
        log.info(f"Beginning auth for user {username}")

        try:
            # Load SSH keys for this user from the database
            async with db.session() as data:
                user_keys = await data.ssh_key(asf_uid=username).all()
                # TODO: This should potentially be migrated to the storage interface
                workflow_keys = await data.workflow_ssh_key(asf_uid=username).all()
                now = int(time.time())
                valid_workflow_keys = []
                for workflow_key in workflow_keys:
                    if workflow_key.expires > now:
                        valid_workflow_keys.append(workflow_key)

                if not (user_keys or valid_workflow_keys):
                    log.warning(f"No SSH keys found for user: {username}")
                    # Still require authentication, but it will fail
                    return True

                # Create an authorized_keys file as a string
                auth_keys_lines = []
                for user_key in user_keys:
                    auth_keys_lines.append(user_key.key)
                for workflow_key in valid_workflow_keys:
                    auth_keys_lines.append(workflow_key.key)

                auth_keys_data = "\n".join(auth_keys_lines)
                log.info(f"Loaded {len(user_keys)} SSH keys for user {username}")

                # Set the authorized keys in the connection
                try:
                    authorized_keys = asyncssh.import_authorized_keys(auth_keys_data)
                    self._conn.set_authorized_keys(authorized_keys)
                    log.info(f"Successfully set authorized keys for {username}")
                except Exception as e:
                    log.error(f"Error setting authorized keys: {e}")

        except Exception as e:
            log.error(f"Database error loading SSH keys: {e}")

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
        log.info(f"Generated SSH host key at {key_path}")

    server = await asyncssh.create_server(
        SSHServer,
        server_host_keys=[key_path],
        process_factory=_step_01_handle_client,
        host=_CONFIG.SSH_HOST,
        port=_CONFIG.SSH_PORT,
        encoding=None,
    )

    log.info(f"SSH server started on {_CONFIG.SSH_HOST}:{_CONFIG.SSH_PORT}")
    return server


async def server_stop(server: asyncssh.SSHAcceptor) -> None:
    """Stop the SSH server."""
    server.close()
    await server.wait_closed()
    log.info("SSH server stopped")


def _fail[T](process: asyncssh.SSHServerProcess, message: str, return_value: T) -> T:
    _output_stderr(process, message)
    if not process.is_closing():
        process.exit(1)
    return return_value


def _output_stderr(process: asyncssh.SSHServerProcess, message: str) -> None:
    """Output a message to the client's stderr."""
    message = f"ATR SSH: {message}"
    log.error(message)
    encoded_message = f"{message}\n".encode()
    try:
        process.stderr.write(encoded_message)
    except BrokenPipeError:
        log.warning("Failed to write error to client stderr: broken pipe")
    except Exception as e:
        log.exception(f"Error writing to client stderr: {e}")


async def _step_01_handle_client(process: asyncssh.SSHServerProcess) -> None:
    """Process client command, validating and dispatching to read or write handlers."""
    try:
        await _step_02_handle_safely(process)
    except RsyncArgsError as e:
        return _fail(process, f"Error: {e}", None)
    except Exception as e:
        log.exception(f"Error during client command processing: {e}")
        return _fail(process, f"Exception: {e}", None)


async def _step_02_handle_safely(process: asyncssh.SSHServerProcess) -> None:
    asf_uid = process.get_extra_info("username")
    log.info(f"Handling command for authenticated user: {asf_uid}")

    if not process.command:
        raise RsyncArgsError("No command specified")

    log.info(f"Received command: {process.command}")
    # TODO: Use shlex.split or similar if commands can contain quoted arguments
    argv = process.command.split()

    ##############################################
    ### Calls _step_03_command_simple_validate ###
    ##############################################
    is_read_request = _step_03_command_simple_validate(argv)

    #######################################
    ### Calls _step_04_command_validate ###
    #######################################
    project_name, version_name, release_obj = await _step_04_command_validate(process, argv, is_read_request)
    # The release object is only present for read requests
    release_name = sql.release_name(project_name, version_name)

    if release_obj is not None:
        log.info(f"Processing READ request for {release_name}")
        ####################################################
        ### Calls _step_07a_process_validated_rsync_read ###
        ####################################################
        await _step_07a_process_validated_rsync_read(process, argv, release_obj)
    else:
        _output_stderr(process, f"Received write command: {process.command}")
        log.info(f"Processing WRITE request for {release_name}")
        #####################################################
        ### Calls _step_07b_process_validated_rsync_write ###
        #####################################################
        await _step_07b_process_validated_rsync_write(process, argv, project_name, version_name)


def _step_03_command_simple_validate(argv: list[str]) -> bool:
    """Validate the basic structure of the rsync command and detect read vs write."""
    # We use our own arg parsing here to be more strict about the syntax
    # READ: ['rsync', '--server', '--sender', '-vlogDtpre.iLsfxCIvu', '.', '/proj/v1/']
    # WRITE: ['rsync', '--server', '-vlogDtpre.iLsfxCIvu', '.', '/proj/v1/']
    argv = argv[:]

    if argv[:2] != ["rsync", "--server"]:
        raise RsyncArgsError("The first two arguments must be rsync and --server")
    argv = argv[2:]

    is_read_request = False
    if argv[:1] == ["--sender"]:
        is_read_request = True
        argv = argv[1:]

    flags = set()
    while argv and argv[0].startswith("-") and (not argv[0].startswith("--")):
        aflags = argv.pop(0)[1:]
        if "e." in aflags:
            aflags = aflags.split("e.", 1)[0]
        flags.update(aflags)
    # The -r flag takes precedence over -d and --dirs
    flags.discard("d")

    if flags != {"D", "g", "l", "o", "p", "r", "t", "v"}:
        raise RsyncArgsError(f"The flags must be -Dgloprtv, got {sorted(flags)}")

    # The -r flag takes precedence over -d and --dirs
    if argv[:1] == ["--dirs"]:
        argv = argv[1:]

    if (not is_read_request) and (argv[:1] == ["--delete"]):
        argv = argv[1:]

    if len(argv) != 2:
        raise RsyncArgsError(f"Expected two path arguments, got {argv}")

    if argv[0] != ".":
        raise RsyncArgsError("The first path argument must be .")
    return is_read_request


async def _step_04_command_validate(
    process: asyncssh.SSHServerProcess, argv: list[str], is_read_request: bool
) -> tuple[str, str, sql.Release | None]:
    """Validate the path and user permissions for read or write."""
    ############################################
    ### Calls _step_05_command_path_validate ###
    ############################################
    path_project, path_version = _step_05_command_path_validate(argv[-1])

    ssh_uid = process.get_extra_info("username")

    async with db.session() as data:
        project = await data.project(name=path_project, status=sql.ProjectStatus.ACTIVE, _committee=True).get()
        if project is None:
            # Projects are public, so existence information is public
            raise RsyncArgsError(f"Project '{path_project}' does not exist")

        release = await data.release(project_name=project.name, version=path_version).get()

    if is_read_request:
        #################################################
        ### Calls _step_06a_validate_read_permissions ###
        #################################################
        validated_release = await _step_06a_validate_read_permissions(
            ssh_uid, project, release, path_project, path_version
        )
        return path_project, path_version, validated_release

    ##################################################
    ### Calls _step_06b_validate_write_permissions ###
    ##################################################
    await _step_06b_validate_write_permissions(ssh_uid, project, release)
    # Return None for the release object for write requests
    return path_project, path_version, None


def _step_05_command_path_validate(path: str) -> tuple[str, str]:
    """Validate the path argument for rsync commands."""
    # READ: rsync --server --sender -vlogDtpre.iLsfxCIvu . /proj/v1/
    # Validating path: /proj/v1/
    # WRITE: rsync --server -vlogDtpre.iLsfxCIvu . /proj/v1/
    # Validating path: /proj/v1/

    if not path.startswith("/"):
        raise RsyncArgsError("The path argument should be an absolute path")

    if not path.endswith("/"):
        # Technically we could ignore this, because we rewrite the path anyway for writes
        # But we should enforce good rsync usage practices
        raise RsyncArgsError("The path argument should be a directory path, ending with a /")

    if "//" in path:
        raise RsyncArgsError("The path argument should not contain //")

    if path.count("/") != 3:
        raise RsyncArgsError("The path argument should be a /PROJECT/VERSION/ directory path")

    path_project, path_version = path.strip("/").split("/", 1)
    alphanum = set(string.ascii_letters + string.digits + "-")
    if not all(c in alphanum for c in path_project):
        raise RsyncArgsError("The project name should contain only alphanumeric characters or hyphens")

    # From a survey of version numbers we find that only . and - are used
    # We also allow + which is in common use
    version_punctuation = set(".-+")
    if path_version[0] not in alphanum:
        # Must certainly not allow the directory to be called "." or ".."
        # And we also want to avoid patterns like ".htaccess"
        raise RsyncArgsError("The version should start with an alphanumeric character")
    if path_version[-1] not in alphanum:
        raise RsyncArgsError("The version should end with an alphanumeric character")
    if not all(c in (alphanum | version_punctuation) for c in path_version):
        raise RsyncArgsError("The version should contain only alphanumeric characters, dots, dashes, or pluses")

    return path_project, path_version


async def _step_06a_validate_read_permissions(
    ssh_uid: str,
    project: sql.Project,
    release: sql.Release | None,
    path_project: str,
    path_version: str,
) -> sql.Release | None:
    """Validate permissions for a read request."""
    if release is None:
        raise RsyncArgsError(f"Release '{path_project}-{path_version}' does not exist")

    allowed_read_phases = {
        sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
        sql.ReleasePhase.RELEASE_CANDIDATE,
        sql.ReleasePhase.RELEASE_PREVIEW,
    }
    if release.phase not in allowed_read_phases:
        raise RsyncArgsError(f"Release '{release.name}' is not in a readable phase ({release.phase.value})")

    if not user.is_committer(project.committee, ssh_uid):
        raise RsyncArgsError(
            f"You must be a committer or committee member for project '{project.name}' to read this release"
        )
    return release


async def _step_06b_validate_write_permissions(
    ssh_uid: str,
    project: sql.Project,
    release: sql.Release | None,
) -> None:
    """Validate permissions for a write request."""
    if release is None:
        # Creating a new release requires committee membership
        if not user.is_committee_member(project.committee, ssh_uid):
            raise RsyncArgsError(f"You must be a member of project '{project.name}' committee to create a release")
    else:
        # Uploading to existing release, requires DRAFT and participant status
        if release.phase != sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
            raise RsyncArgsError(
                f"Cannot upload: Release '{release.name}' is no longer in draft phase ({release.phase.value})"
            )

        if not user.is_committer(project.committee, ssh_uid):
            raise RsyncArgsError(
                f"You must be a committer or committee member for project '{project.name}' to upload to this release"
            )


async def _step_07a_process_validated_rsync_read(
    process: asyncssh.SSHServerProcess,
    argv: list[str],
    release: sql.Release,
) -> None:
    """Handle a validated rsync read request."""
    exit_status = 1
    try:
        # Determine the source directory based on the release phase and revision
        source_dir = util.release_directory(release)
        log.info(
            f"Identified source directory for read: {source_dir} for release "
            f"{release.name} (phase {release.phase.value})"
        )

        # Check whether the source directory actually exists before proceeding
        if not await aiofiles.os.path.isdir(source_dir):
            raise RsyncArgsError(f"Source directory '{source_dir}' not found for release {release.name}")

        # Update the rsync command path to the determined source directory
        argv[-1] = str(source_dir)
        if not argv[-1].endswith("/"):
            argv[-1] += "/"

        ###################################################
        ### Calls _step_08_execute_rsync_sender_command ###
        ###################################################
        exit_status = await _step_08_execute_rsync(process, argv)
        if exit_status != 0:
            log.error(
                f"rsync --sender failed with exit status {exit_status} for release {release.name}. "
                f"Command: {process.command} (run as {' '.join(argv)})"
            )

        if not process.is_closing():
            process.exit(exit_status)

    except Exception as e:
        log.exception(f"Error during rsync read processing for {release.name}")
        raise RsyncArgsError(f"Internal error processing read request: {e}")


async def _step_07b_process_validated_rsync_write(
    process: asyncssh.SSHServerProcess,
    argv: list[str],
    project_name: str,
    version_name: str,
) -> None:
    """Handle a validated rsync write request."""
    asf_uid = process.get_extra_info("username")
    exit_status = 0
    release_name = sql.release_name(project_name, version_name)

    # Ensure the release object exists or is created
    # This must happen before creating the revision directory
    #######################################################
    ### Calls _step_07c_ensure_release_object_for_write ###
    #######################################################
    await _step_07c_ensure_release_object_for_write(project_name, version_name)

    # Create the draft revision directory structure
    description = "File synchronisation through ssh, using rsync"
    async with storage.write(asf_uid) as write:
        wacp = await write.as_project_committee_participant(project_name)
        async with wacp.revision.create_and_manage(
            project_name, version_name, asf_uid, description=description
        ) as creating:
            # Uses new_revision_number for logging only
            if creating.old is not None:
                log.info(f"Using old revision {creating.old.number} and interim path {creating.interim_path}")
            # Update the rsync command path to the new revision directory
            argv[-1] = str(creating.interim_path)

            ###################################################
            ### Calls _step_08_execute_rsync_upload_command ###
            ###################################################
            exit_status = await _step_08_execute_rsync(process, argv)
            if exit_status != 0:
                if creating.old is not None:
                    for_revision = f"successor of revision {creating.old.number}"
                else:
                    for_revision = f"initial revision for release {release_name}"
                log.error(
                    f"rsync upload failed with exit status {exit_status} for {for_revision}. "
                    f"Command: {process.command} (run as {' '.join(argv)})"
                )
                raise types.FailedError(f"rsync upload failed with exit status {exit_status} for {for_revision}")

        if creating.new is not None:
            log.info(f"rsync upload successful for revision {creating.new.number}")
            host = config.get().APP_HOST
            message = f"\nATR: Created revision {creating.new.number} of {project_name} {version_name}\n"
            message += f"ATR: https://{host}/compose/{project_name}/{version_name}\n"
            if not process.stderr.is_closing():
                process.stderr.write(message.encode())
                await process.stderr.drain()
        else:
            log.info(f"rsync upload unsuccessful for release {release_name}")

        # If we got here, there was no exception
        if not process.is_closing():
            process.exit(exit_status)


async def _step_07c_ensure_release_object_for_write(project_name: str, version_name: str) -> None:
    """Ensure the release object exists or create it for a write operation."""
    release_name = sql.release_name(project_name, version_name)
    async with db.session() as data:
        release = await data.release(name=sql.release_name(project_name, version_name), _committee=True).get()
        if release is None:
            project = await data.project(name=project_name, status=sql.ProjectStatus.ACTIVE, _committee=True).demand(
                RuntimeError("Project not found after validation")
            )
            if version_name_error := util.version_name_error(version_name):
                # This should ideally be caught by path validation, but double check
                raise RuntimeError(f'Invalid version name "{version_name}": {version_name_error}')
            # Create a new release object
            log.info(f"Creating new release object for {release_name}")
            release = sql.Release(
                project_name=project.name,
                project=project,
                version=version_name,
                phase=sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
                created=datetime.datetime.now(datetime.UTC),
            )
            data.add(release)
        elif release.phase != sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
            raise RsyncArgsError(f"Release '{release.name}' is no longer in draft phase ({release.phase.value})")
        await data.commit()


async def _step_08_execute_rsync(process: asyncssh.SSHServerProcess, argv: list[str]) -> int:
    """Execute the modified rsync command."""
    log.info(f"Executing modified rsync command: {' '.join(argv)}")
    proc = await asyncio.create_subprocess_shell(
        " ".join(argv),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    # Redirect the client's streams to the rsync process
    # TODO: Do we instead need send_eof=False on stderr only?
    # , stdout=proc.stdout
    # , stderr=proc.stderr
    # , send_eof=False
    await process.redirect(stdin=proc.stdin, stdout=proc.stdout, send_eof=False)
    # Wait for rsync to finish and get its exit status
    exit_status = await proc.wait()
    log.info(f"Rsync finished with exit status {exit_status}")
    return exit_status
