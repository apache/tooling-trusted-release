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
import logging
import os
from typing import Final

import aiofiles
import aiofiles.os
import asyncssh

import atr.config as config

_LOGGER: Final = logging.getLogger(__name__)
_AUTHORIZED_KEY_PATH: Final = "allowed_ssh_key.pub"
_CONFIG: Final = config.get()


class _SSHServer(asyncssh.SSHServer):
    """Simple SSH server that handles connections."""

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        """Called when a connection is established."""
        peer_addr = conn.get_extra_info("peername")[0]
        _LOGGER.info(f"SSH connection received from {peer_addr}")

    def connection_lost(self, exc: Exception | None) -> None:
        """Called when a connection is lost or closed."""
        if exc:
            _LOGGER.error(f"SSH connection error: {exc}")
        else:
            _LOGGER.info("SSH connection closed")

    def begin_auth(self, username: str) -> bool:
        """Begin authentication for the specified user."""
        _LOGGER.info(f"Beginning auth for user {username}")
        # Returning True means that we always require authentication
        return True

    def public_key_auth_supported(self) -> bool:
        """Indicate whether public key authentication is supported."""
        return True

    async def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        """Validate a public key against our authorized key."""
        _LOGGER.info(f"Validating public key for user: {username}")

        try:
            return await self._validate_public_key_core(username, key)
        except Exception as e:
            _LOGGER.error(f"Error validating public key: {e}")
            return False

    async def _validate_public_key_core(self, username: str, key: asyncssh.SSHKey) -> bool:
        # We'll be loading keys dynamically from our database
        # Therefore we can't use the authorized_client_keys parameter to asyncssh.create_server

        # Get the full path to the authorized keys file
        auth_key_path = os.path.join(_CONFIG.STATE_DIR, _AUTHORIZED_KEY_PATH)

        # Check whether the authorized key file exists
        if not await aiofiles.os.path.exists(auth_key_path):
            _LOGGER.error(f"Authorized key file not found at {auth_key_path}")
            return False

        # Read the authorized key from file
        async with aiofiles.open(auth_key_path) as f:
            authorized_key_data = await f.read()
        authorized_key_data = authorized_key_data.strip()

        # Create SSHKey object from the authorized key data
        try:
            authorized_key = asyncssh.import_public_key(authorized_key_data)
        except Exception as e:
            _LOGGER.error(f"Failed to import authorized key: {e}")
            return False

        # Compare the keys
        # This is performing authorization, not authentication
        # The authentication takes place in connection.py validate_public_key
        # It calls key.verify
        if key.get_fingerprint() == authorized_key.get_fingerprint():
            _LOGGER.info(f"Public key validated for user: {username}")
            return True
        else:
            _LOGGER.warning(f"Public key validation failed for user: {username}")
            return False


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

    # Check for authorized key
    auth_key_path = os.path.join(_CONFIG.STATE_DIR, _AUTHORIZED_KEY_PATH)
    if not await aiofiles.os.path.exists(auth_key_path):
        _LOGGER.warning(f"No authorized key file found at {auth_key_path}. SSH authentication will fail.")

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


async def _command_validate(process: asyncssh.SSHServerProcess) -> list[str] | None:
    def fail(message: str) -> list[str] | None:
        # NOTE: Changing the return type to just None really confuses mypy
        _LOGGER.error(message)
        process.exit(1)
        return None

    command = process.command
    if not command:
        return fail("No command specified")

    _LOGGER.info(f"Command received: {command}")
    argv = command.split()

    if len(argv) != 5:
        return fail("There should be 5 arguments")

    if argv[0] != "rsync":
        return fail("The first argument should be rsync")

    if argv[1] != "--server":
        return fail("The second argument should be --server")

    # TODO: Might need to accept permutations of this
    # Also certain versions of rsync might change the options
    acceptable_options: Final[str] = "vlogDtpre"
    if not argv[2].startswith(f"-{acceptable_options}."):
        return fail(f"The third argument should start with -{acceptable_options}.")

    if not argv[2][len(f"-{acceptable_options}.") :].isalpha():
        return fail("The third argument should be a valid command")

    if argv[3] != ".":
        return fail("The fourth argument should be .")

    if argv[4] != "/":
        return fail("The fifth argument should be /")

    return argv


async def _handle_client(process: asyncssh.SSHServerProcess) -> None:
    """Process client command by executing it and redirecting I/O."""
    argv = await _command_validate(process)
    if not argv:
        return

    # TODO: We'll have to hook this up to the actual file areas
    # Or, more likely, do post-processing to copy
    argv[4] = os.path.join(_CONFIG.STATE_DIR, "rsync-files")
    _LOGGER.info(f"Modified command: {argv}")

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

        # Wait for the process to complete and exit with its status
        exit_status = await proc.wait()
        process.exit(exit_status)

    except Exception as e:
        _LOGGER.error(f"Error executing command: {e}")
        process.stderr.write(f"Error: {e!s}\n")
        process.exit(1)
