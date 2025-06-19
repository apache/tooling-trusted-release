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


class SSHServer(asyncssh.SSHServer):
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
        SSHServer,
        server_host_keys=[key_path],
        process_factory=_step_01_handle_client,
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


def _fail[T](process: asyncssh.SSHServerProcess, message: str, return_value: T) -> T:
    _LOGGER.error(message)
    # Ensure message is encoded before writing to stderr
    encoded_message = f"ATR SSH error: {message}\n".encode()
    try:
        process.stderr.write(encoded_message)
    except BrokenPipeError:
        _LOGGER.warning("Failed to write error to client stderr: Broken pipe")
    except Exception as e:
        _LOGGER.exception(f"Error writing to client stderr: {e}")
    process.exit(1)
    return return_value


async def _step_01_handle_client(process: asyncssh.SSHServerProcess) -> None:
    """Process client command, validating and dispatching to read or write handlers."""
    asf_uid = process.get_extra_info("username")
    _LOGGER.info(f"Handling command for authenticated user: {asf_uid}")

    if not process.command:
        return _fail(process, "No command specified", None)

    _LOGGER.info(f"Command received: {process.command}")
    # TODO: Use shlex.split or similar if commands can contain quoted arguments
    argv = process.command.split()

    ##############################################
    ### Calls _step_02_command_simple_validate ###
    ##############################################
    simple_validation_error, path_index, is_read_request = _step_02_command_simple_validate(argv)
    if simple_validation_error:
        return _fail(process, f"{simple_validation_error}\nCommand: {process.command}", None)

    #######################################
    ### Calls _step_04_command_validate ###
    #######################################
    validation_results = await _step_04_command_validate(process, argv, path_index, is_read_request)
    if not validation_results:
        return

    # Unpack results
    # The release object is only present for read requests
    project_name, version_name, release_obj = validation_results
    release_name = models.release_name(project_name, version_name)

    if is_read_request:
        if release_obj is None:
            # This should not happen if the validation logic is correct
            return _fail(process, "Internal error: Release object missing for read request after validation", None)
        _LOGGER.info(f"Processing READ request for {release_name}")
        ####################################################
        ### Calls _step_07a_process_validated_rsync_read ###
        ####################################################
        await _step_07a_process_validated_rsync_read(process, argv, path_index, release_obj)
    else:
        _LOGGER.info(f"Processing WRITE request for {release_name}")
        #####################################################
        ### Calls _step_07b_process_validated_rsync_write ###
        #####################################################
        await _step_07b_process_validated_rsync_write(process, argv, path_index, project_name, version_name)


def _step_02_command_simple_validate(argv: list[str]) -> tuple[str | None, int, bool]:
    """Validate the basic structure of the rsync command and detect read vs write."""
    # READ: ['rsync', '--server', '--sender', '-vlogDtpre.iLsfxCIvu', '.', '/proj/v1/']
    # WRITE: ['rsync', '--server', '-vlogDtpre.iLsfxCIvu', '.', '/proj/v1/']

    if not argv:
        return "Empty command", -1, False

    if argv[0] != "rsync":
        return "The first argument must be rsync", -1, False

    if argv[1] != "--server":
        return "The second argument must be --server", -1, False

    is_read_request = False
    option_index = 2

    # Check for --sender flag, which indicates a read request
    if (len(argv) > 2) and (argv[2] == "--sender"):
        is_read_request = True
        option_index = 3
        if len(argv) <= option_index:
            return "Missing options after --sender", -1, True
    elif len(argv) <= 2:
        return "Missing options argument", -1, False

    # Validate the options argument strictly
    options = argv[option_index]
    if "e." in options:
        options = options.split("e.", 1)[0]
    if options != "-vlogDtpr":
        return "The options argument (after --sender) must be '-vlogDtpr[.e<FLAGS>]'", -1, True

    ####################################################
    ### Calls _step_03_validate_rsync_args_structure ###
    ####################################################
    error, path_index = _step_03_validate_rsync_args_structure(argv, option_index, is_read_request)
    if error:
        return error, -1, is_read_request

    return None, path_index, is_read_request


def _step_03_validate_rsync_args_structure(
    argv: list[str], option_index: int, is_read_request: bool
) -> tuple[str | None, int]:
    """Validate the dot argument and path argument presence and count."""
    # READ: ['rsync', '--server', '--sender', '-vlogDtpre.iLsfxCIvu', '.', '/proj/v1/'] :: 3 :: True
    # WRITE: ['rsync', '--server', '-vlogDtpre.iLsfxCIvu', '.', '/proj/v1/'] :: 2 :: False
    dot_arg_index = option_index + 1
    path_index = option_index + 2

    # Write requests might have --delete
    has_delete = False
    if (not is_read_request) and (len(argv) > dot_arg_index) and (argv[dot_arg_index] == "--delete"):
        has_delete = True
        dot_arg_index += 1
        path_index += 1

    if (len(argv) <= dot_arg_index) or (argv[dot_arg_index] != "."):
        expected_pos = "fourth" if (is_read_request or (not has_delete)) else "fifth"
        return f"The {expected_pos} argument must be .", -1

    if len(argv) <= path_index:
        return "Missing path argument", -1

    # Check expected total number of arguments
    expected_len = path_index + 1
    if len(argv) != expected_len:
        return f"Expected {expected_len} arguments, but got {len(argv)}", -1

    return None, path_index


async def _step_04_command_validate(
    process: asyncssh.SSHServerProcess, argv: list[str], path_index: int, is_read_request: bool
) -> tuple[str, str, models.Release | None] | None:
    """Validate the path and user permissions for read or write."""
    ############################################
    ### Calls _step_05_command_path_validate ###
    ############################################
    result = _step_05_command_path_validate(argv[path_index])
    if isinstance(result, str):
        return _fail(process, result, None)
    path_project, path_version = result

    ssh_uid = process.get_extra_info("username")

    async with db.session() as data:
        project = await data.project(name=path_project, status=models.ProjectStatus.ACTIVE, _committee=True).get()
        if project is None:
            # Projects are public, so existence information is public
            return _fail(process, f"Project '{path_project}' does not exist", None)

        release = await data.release(project_name=project.name, version=path_version).get()

        if is_read_request:
            #################################################
            ### Calls _step_06a_validate_read_permissions ###
            #################################################
            validated_release, success = await _step_06a_validate_read_permissions(
                process, ssh_uid, project, release, path_project, path_version
            )
            if success is None:
                return None
            return path_project, path_version, validated_release
        else:
            ##################################################
            ### Calls _step_06b_validate_write_permissions ###
            ##################################################
            success = await _step_06b_validate_write_permissions(process, ssh_uid, project, release)
            if success is None:
                return None
            # Return None for the release object for write requests
            return path_project, path_version, None


def _step_05_command_path_validate(path: str) -> tuple[str, str] | str:
    """Validate the path argument for rsync commands."""
    # READ: rsync --server --sender -vlogDtpre.iLsfxCIvu . /proj/v1/
    # Validating path: /proj/v1/
    # WRITE: rsync --server -vlogDtpre.iLsfxCIvu . /proj/v1/
    # Validating path: /proj/v1/

    if not path.startswith("/"):
        return "The path argument should be an absolute path"

    if not path.endswith("/"):
        # Technically we could ignore this, because we rewrite the path anyway for writes
        # But we should enforce good rsync usage practices
        return "The path argument should be a directory path, ending with a /"

    if "//" in path:
        return "The path argument should not contain //"

    if path.count("/") != 3:
        return "The path argument should be a /PROJECT/VERSION/ directory path"

    path_project, path_version = path.strip("/").split("/", 1)
    alphanum = set(string.ascii_letters + string.digits + "-")
    if not all(c in alphanum for c in path_project):
        return "The project name should contain only alphanumeric characters or hyphens"

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


async def _step_06a_validate_read_permissions(
    process: asyncssh.SSHServerProcess,
    ssh_uid: str,
    project: models.Project,
    release: models.Release | None,
    path_project: str,
    path_version: str,
) -> tuple[models.Release | None, bool]:
    """Validate permissions for a read request."""
    if release is None:
        _fail(process, f"Release '{path_project}-{path_version}' does not exist", None)
        return None, False

    allowed_read_phases = {
        models.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
        models.ReleasePhase.RELEASE_CANDIDATE,
        models.ReleasePhase.RELEASE_PREVIEW,
    }
    if release.phase not in allowed_read_phases:
        _fail(process, f"Release '{release.name}' is not in a readable phase ({release.phase.value})", None)
        return None, False

    if not user.is_committer(project.committee, ssh_uid):
        _fail(
            process,
            f"You must be a committer or committee member for project '{project.name}' to read this release",
            None,
        )
        return None, False
    return release, True


async def _step_06b_validate_write_permissions(
    process: asyncssh.SSHServerProcess,
    ssh_uid: str,
    project: models.Project,
    release: models.Release | None,
) -> bool:
    """Validate permissions for a write request."""
    if release is None:
        # Creating a new release requires committee membership
        if not user.is_committee_member(project.committee, ssh_uid):
            return _fail(
                process,
                f"You must be a member of project '{project.name}' committee to create a release",
                False,
            )
    else:
        # Uploading to existing release, requires DRAFT and participant status
        if release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
            return _fail(
                process,
                f"Cannot upload: Release '{release.name}' is no longer in draft phase ({release.phase.value})",
                False,
            )

        if not user.is_committer(project.committee, ssh_uid):
            return _fail(
                process,
                f"You must be a committer or committee member for project '{project.name}' "
                "to upload to this draft release",
                False,
            )
    return True


async def _step_07a_process_validated_rsync_read(
    process: asyncssh.SSHServerProcess,
    argv: list[str],
    path_index: int,
    release: models.Release,
) -> None:
    """Handle a validated rsync read request."""
    exit_status = 1
    try:
        # Determine the source directory based on the release phase and revision
        source_dir = util.release_directory(release)
        _LOGGER.info(
            f"Identified source directory for read: {source_dir} for release "
            f"{release.name} (phase {release.phase.value})"
        )

        # Check whether the source directory actually exists before proceeding
        if not await aiofiles.os.path.isdir(source_dir):
            return _fail(process, f"Source directory '{source_dir}' not found for release {release.name}", None)

        # Update the rsync command path to the determined source directory
        argv[path_index] = str(source_dir)
        if not argv[path_index].endswith("/"):
            argv[path_index] += "/"

        ###################################################
        ### Calls _step_08_execute_rsync_sender_command ###
        ###################################################
        exit_status = await _step_08_execute_rsync(process, argv)
        if exit_status != 0:
            _LOGGER.error(
                f"rsync --sender failed with exit status {exit_status} for release {release.name}. "
                f"Command: {process.command} (run as {' '.join(argv)})"
            )

        if not process.is_closing():
            process.exit(exit_status)

    except Exception as e:
        _LOGGER.exception(f"Error during rsync read processing for {release.name}")
        _fail(process, f"Internal error processing read request: {e}", None)
        process.exit(1)


async def _step_07b_process_validated_rsync_write(
    process: asyncssh.SSHServerProcess,
    argv: list[str],
    path_index: int,
    project_name: str,
    version_name: str,
) -> None:
    """Handle a validated rsync write request."""
    asf_uid = process.get_extra_info("username")
    exit_status = 1

    release_name = models.release_name(project_name, version_name)
    try:
        # Ensure the release object exists or is created
        # This must happen before creating the revision directory
        #######################################################
        ### Calls _step_07c_ensure_release_object_for_write ###
        #######################################################
        if not await _step_07c_ensure_release_object_for_write(process, project_name, version_name):
            # The _fail function was already called in _07b2_ensure_release_object_for_write
            return

        # Create the draft revision directory structure
        description = "File synchronisation through ssh, using rsync"
        async with revision.create_and_manage(project_name, version_name, asf_uid, description=description) as creating:
            # Uses new_revision_number for logging only
            if creating.old is not None:
                _LOGGER.info(f"Using old revision {creating.old.number} and interim path {creating.interim_path}")
            # Update the rsync command path to the new revision directory
            argv[path_index] = str(creating.interim_path)

            ###################################################
            ### Calls _step_08_execute_rsync_upload_command ###
            ###################################################
            exit_status = await _step_08_execute_rsync(process, argv)
            if exit_status != 0:
                if creating.old is not None:
                    for_revision = f"successor of revision {creating.old.number}"
                else:
                    for_revision = f"initial revision for release {release_name}"
                _LOGGER.error(
                    f"rsync upload failed with exit status {exit_status} for {for_revision}. "
                    f"Command: {process.command} (run as {' '.join(argv)})"
                )
                raise revision.FailedError(f"rsync upload failed with exit status {exit_status} for {for_revision}")
        if creating.new is not None:
            _LOGGER.info(f"rsync upload successful for revision {creating.new.number}")
            host = config.get().APP_HOST
            message = f"\nATR: Created revision {creating.new.number} of {project_name} {version_name}\n"
            message += f"ATR: https://{host}/compose/{project_name}/{version_name}\n"
            if not process.stderr.is_closing():
                process.stderr.write(message.encode())
                await process.stderr.drain()
        else:
            _LOGGER.info(f"rsync upload unsuccessful for release {release_name}")
        if not process.is_closing():
            process.exit(exit_status)

    except Exception as e:
        _LOGGER.exception(f"Error during draft revision processing for {release_name}")
        _fail(process, f"Internal error processing upload revision: {e}", None)
        if not process.is_closing():
            process.exit(1)


async def _step_07c_ensure_release_object_for_write(
    process: asyncssh.SSHServerProcess, project_name: str, version_name: str
) -> bool:
    """Ensure the release object exists or create it for a write operation."""
    release_name = models.release_name(project_name, version_name)
    try:
        async with db.session() as data:
            async with data.begin():
                release = await data.release(
                    name=models.release_name(project_name, version_name), _committee=True
                ).get()
                if release is None:
                    project = await data.project(
                        name=project_name, status=models.ProjectStatus.ACTIVE, _committee=True
                    ).demand(RuntimeError("Project not found after validation"))
                    if version_name_error := util.version_name_error(version_name):
                        # This should ideally be caught by path validation, but double check
                        raise RuntimeError(f'Invalid version name "{version_name}": {version_name_error}')
                    # Create a new release object
                    _LOGGER.info(f"Creating new release object for {release_name}")
                    release = models.Release(
                        project_name=project.name,
                        project=project,
                        version=version_name,
                        phase=models.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
                        created=datetime.datetime.now(datetime.UTC),
                    )
                    data.add(release)
                elif release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
                    return _fail(
                        process,
                        f"Release '{release.name}' is no longer in draft phase ({release.phase.value}) "
                        "- cannot create new revision",
                        False,
                    )
        return True
    except Exception as e:
        _LOGGER.exception(f"Error ensuring release object for write: {release_name}")
        return _fail(process, f"Internal error ensuring release object: {e}", False)


async def _step_08_execute_rsync(process: asyncssh.SSHServerProcess, argv: list[str]) -> int:
    """Execute the modified rsync command."""
    _LOGGER.info(f"Executing modified rsync command: {' '.join(argv)}")
    proc = await asyncio.create_subprocess_shell(
        " ".join(argv),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    # Redirect the client's streams to the rsync process
    # TODO: Do we instead need send_eof=False on stderr only?
    await process.redirect(stdin=proc.stdin, stdout=proc.stdout, stderr=proc.stderr, send_eof=False)
    # Wait for rsync to finish and get its exit status
    exit_status = await proc.wait()
    _LOGGER.info(f"Rsync finished with exit status {exit_status}")
    return exit_status
