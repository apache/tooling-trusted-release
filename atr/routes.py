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

"""routes.py"""

import asyncio
import datetime
import functools
import hashlib
import logging
import logging.handlers
import pprint
import secrets
import shutil
import tempfile
import time
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, ParamSpec, TypeVar, cast

import aiofiles
import aiofiles.os
import gnupg
from quart import Request, flash, redirect, render_template, request, send_file, url_for
from quart.wrappers.response import Response as QuartResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlmodel import select
from werkzeug.datastructures import FileStorage
from werkzeug.wrappers.response import Response

from asfquart import APP
from asfquart.auth import Requirements, require
from asfquart.base import ASFQuartException
from asfquart.session import ClientSession
from asfquart.session import read as session_read
from atr.db.models import (
    PMC,
    Package,
    PMCKeyLink,
    ProductLine,
    PublicSigningKey,
    Release,
    ReleasePhase,
    ReleaseStage,
    Task,
    TaskStatus,
)

from .db import get_session
from .db.service import get_pmc_by_name, get_pmcs
from .util import compute_sha512, get_release_storage_dir

if APP is ...:
    raise ValueError("APP is not set")


P = ParamSpec("P")
T = TypeVar("T")

# TODO: Should get this from config, checking debug there
measure_performance = True

# |         1 | RSA (Encrypt or Sign) [HAC]                        |
# |         2 | RSA Encrypt-Only [HAC]                             |
# |         3 | RSA Sign-Only [HAC]                                |
# |        16 | Elgamal (Encrypt-Only) [ELGAMAL] [HAC]             |
# |        17 | DSA (Digital Signature Algorithm) [FIPS186] [HAC]  |
# |        18 | ECDH public key algorithm                          |
# |        19 | ECDSA public key algorithm [FIPS186]               |
# |        20 | Reserved (formerly Elgamal Encrypt or Sign)        |
# |        21 | Reserved for Diffie-Hellman                        |
# |           | (X9.42, as defined for IETF-S/MIME)                |
# |        22 | EdDSA [I-D.irtf-cfrg-eddsa]                        |
# - https://lists.gnupg.org/pipermail/gnupg-devel/2017-April/032762.html
# TODO: (Obviously we should move this, but where to?)
algorithms = {
    1: "RSA",
    2: "RSA",
    3: "RSA",
    16: "Elgamal",
    17: "DSA",
    18: "ECDH",
    19: "ECDSA",
    21: "Diffie-Hellman",
    22: "EdDSA",
}


class FlashError(RuntimeError): ...


class MicrosecondsFormatter(logging.Formatter):
    # Answers on a postcard if you know why Python decided to use a comma by default
    default_msec_format = "%s.%03d"


class AsyncFileHandler(logging.Handler):
    """A logging handler that writes logs asynchronously using aiofiles."""

    def __init__(self, filename, mode="w", encoding=None):
        super().__init__()
        self.filename = filename

        if mode != "w":
            raise RuntimeError("Only write mode is supported")

        self.encoding = encoding
        self.queue = asyncio.Queue()
        self.our_worker_task = None

    def our_worker_task_ensure(self):
        """Lazily create the worker task if it doesn't exist and there's an event loop."""
        if self.our_worker_task is None:
            try:
                loop = asyncio.get_running_loop()
                self.our_worker_task = loop.create_task(self.our_worker())
            except RuntimeError:
                # No event loop running yet, try again on next emit
                ...

    async def our_worker(self):
        """Background task that writes queued log messages to file."""
        while True:
            record = await self.queue.get()
            if record is None:
                break

            try:
                # Format the log record first
                formatted_message = self.format(record) + "\n"
                message_bytes = formatted_message.encode(self.encoding or "utf-8")

                # Use a binary mode literal with aiofiles.open
                # https://github.com/Tinche/aiofiles/blob/main/src/aiofiles/threadpool/__init__.py
                # We should be able to use any mode, but pyright requires a binary mode
                async with aiofiles.open(self.filename, "wb+") as f:
                    await f.write(message_bytes)
            except Exception:
                self.handleError(record)
            finally:
                self.queue.task_done()

    def emit(self, record):
        """Queue the record for writing by the worker task."""
        try:
            # Ensure worker task is running
            self.our_worker_task_ensure()

            # Queue the record, but handle the case where no event loop is running yet
            try:
                self.queue.put_nowait(record)
            except RuntimeError:
                # If there's no event loop, log synchronously as fallback
                with open(self.filename, "w", encoding=self.encoding) as f:
                    f.write(self.format(record) + "\n")
        except Exception:
            self.handleError(record)

    def close(self):
        """Shut down the worker task cleanly."""
        if self.our_worker_task is not None and not self.our_worker_task.done():
            try:
                self.queue.put_nowait(None)
            except RuntimeError:
                # No running event loop, no need to clean up
                ...
        super().close()


# Setup a dedicated logger for route performance metrics
route_logger = logging.getLogger("route.performance")
# Use custom formatter that properly includes microseconds
# TODO: Is this actually UTC?
route_logger_handler = AsyncFileHandler("route-performance.log")
route_logger_handler.setFormatter(MicrosecondsFormatter("%(asctime)s - %(message)s"))
route_logger.addHandler(route_logger_handler)
route_logger.setLevel(logging.INFO)
# If we don't set propagate to False then it logs to the term as well
route_logger.propagate = False


def app_route(path: str, methods: list[str] | None = None):
    """Register a route with the Flask app with built-in performance logging."""

    def decorator(f):
        # First apply our performance measuring decorator
        if measure_performance:
            measured_func = app_route_performance_measure(path, methods)(f)
        else:
            measured_func = f
        # Then apply the original route decorator
        return APP.route(path, methods=methods)(measured_func)

    return decorator


def app_route_performance_measure(route_path: str, http_methods: list[str] | None = None) -> Callable:
    """Decorator that measures and logs route performance with path and method information."""

    # def format_time(seconds: float) -> str:
    #     """Format time in appropriate units (µs or ms)."""
    #     microseconds = seconds * 1_000_000
    #     if microseconds < 1000:
    #         return f"{microseconds:.2f} µs"
    #     else:
    #         milliseconds = microseconds / 1000
    #         return f"{milliseconds:.2f} ms"

    def decorator(f: Callable[P, Coroutine[Any, Any, T]]) -> Callable[P, Awaitable[T]]:
        @functools.wraps(f)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            # This wrapper is based on an outstanding idea by Mostafa Farzán
            # Farzán realised that we can step the event loop manually
            # That way, we can also divide it into synchronous and asynchronous parts
            # The synchronous part is done using coro.send(None)
            # The asynchronous part is done using asyncio.sleep(0)
            # We use two methods for measuring the async part, and take the largest
            # This performance measurement adds a bit of overhead, about 10-20ms
            # Therefore it should be avoided in production, or made more efficient
            # We could perhaps use for a small portion of requests
            blocking_time = 0.0
            async_time = 0.0
            loop_time = 0.0
            total_start = time.perf_counter()
            coro = f(*args, **kwargs)
            try:
                while True:
                    # Measure the synchronous part
                    sync_start = time.perf_counter()
                    future = coro.send(None)
                    sync_end = time.perf_counter()
                    blocking_time += sync_end - sync_start

                    # Measure the asynchronous part in two different ways
                    loop = asyncio.get_running_loop()
                    wait_start = time.perf_counter()
                    loop_start = loop.time()
                    while not future.done():
                        await asyncio.sleep(0)
                    wait_end = time.perf_counter()
                    loop_end = loop.time()
                    async_time += wait_end - wait_start
                    loop_time += loop_end - loop_start

                    # Raise exception if any
                    future.result()
            except StopIteration as e:
                total_end = time.perf_counter()
                total_time = total_end - total_start

                methods_str = ",".join(http_methods) if http_methods else "GET"

                nonblocking_time = max(async_time, loop_time)
                # If async time is more than 10% different from loop time, log it
                delta_symbol = "="
                nonblocking_delta = abs(async_time - loop_time)
                # Must check that nonblocking_time is not 0 to avoid division by zero
                if nonblocking_time and ((nonblocking_delta / nonblocking_time) > 0.1):
                    delta_symbol = "!"
                route_logger.info(
                    "%s %s %s %s %s %s %s",
                    methods_str,
                    route_path,
                    f.__name__,
                    delta_symbol,
                    int(blocking_time * 1000),
                    int(nonblocking_time * 1000),
                    int(total_time * 1000),
                )

                return e.value

        return wrapper

    return decorator


@asynccontextmanager
async def ephemeral_gpg_home():
    """Create a temporary directory for an isolated GPG home, and clean it up on exit."""
    # TODO: This is only used in key_user_add
    # We could even inline it there
    temp_dir = await asyncio.to_thread(tempfile.mkdtemp, prefix="gpg-")
    try:
        yield temp_dir
    finally:
        await asyncio.to_thread(shutil.rmtree, temp_dir)


async def file_hash_save(base_dir: Path, file: FileStorage) -> tuple[str, int]:
    """
    Save a file using its SHA3-256 hash as the filename.
    Returns the hash and size in bytes of the saved file.
    """
    sha3 = hashlib.sha3_256()
    total_bytes = 0

    # Create temporary file to stream to while computing hash
    temp_path = base_dir / f"temp-{secrets.token_hex(8)}"
    try:
        stream = file.stream

        async with aiofiles.open(temp_path, "wb") as f:
            while True:
                chunk = await asyncio.to_thread(stream.read, 8192)
                if not chunk:
                    break
                sha3.update(chunk)
                total_bytes += len(chunk)
                await f.write(chunk)

        file_hash = sha3.hexdigest()
        final_path = base_dir / file_hash

        # Only move to final location if it doesn't exist
        # This can race, but it's hash based so it's okay
        if not await aiofiles.os.path.exists(final_path):
            await aiofiles.os.rename(temp_path, final_path)
        else:
            # If file already exists, just remove the temp file
            await aiofiles.os.remove(temp_path)

        return file_hash, total_bytes
    except Exception as e:
        if await aiofiles.os.path.exists(temp_path):
            await aiofiles.os.remove(temp_path)
        raise e


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


def format_artifact_name(project_name: str, product_name: str, version: str, is_podling: bool = False) -> str:
    """Format an artifact name according to Apache naming conventions.

    For regular projects: apache-${project}-${product}-${version}
    For podlings: apache-${project}-incubating-${product}-${version}
    """
    if is_podling:
        return f"apache-{project_name}-incubating-{product_name}-{version}"
    return f"apache-{project_name}-{product_name}-{version}"


async def key_add_post(session: ClientSession, request: Request, user_pmcs: Sequence[PMC]) -> dict | None:
    form = await request.form
    public_key = form.get("public_key")
    if not public_key:
        raise FlashError("Public key is required")

    # Get selected PMCs from form
    selected_pmcs = form.getlist("selected_pmcs")
    if not selected_pmcs:
        raise FlashError("You must select at least one PMC")

    # Ensure that the selected PMCs are ones of which the user is actually a member
    invalid_pmcs = [pmc for pmc in selected_pmcs if (pmc not in session.committees) and (pmc not in session.projects)]
    if invalid_pmcs:
        raise FlashError(f"Invalid PMC selection: {', '.join(invalid_pmcs)}")

    return await key_user_add(session, public_key, selected_pmcs)


async def key_user_add(session: ClientSession, public_key: str, selected_pmcs: list[str]) -> dict | None:
    if not public_key:
        raise FlashError("Public key is required")

    # Import the key into GPG to validate and extract info
    # TODO: We'll just assume for now that gnupg.GPG() doesn't need to be async
    async with ephemeral_gpg_home() as gpg_home:
        gpg = gnupg.GPG(gnupghome=gpg_home)
        import_result = await asyncio.to_thread(gpg.import_keys, public_key)

        if not import_result.fingerprints:
            raise FlashError("Invalid public key format")

        fingerprint = import_result.fingerprints[0]
        if fingerprint is not None:
            fingerprint = fingerprint.lower()
        # APP.logger.info("Import result: %s", vars(import_result))
        # Get key details
        # We could probably use import_result instead
        # But this way it shows that they've really been imported
        keys = await asyncio.to_thread(gpg.list_keys)

    # Then we have the properties listed here:
    # https://gnupg.readthedocs.io/en/latest/#listing-keys
    # Note that "fingerprint" is not listed there, but we have it anyway...
    key = next((k for k in keys if (k["fingerprint"] is not None) and (k["fingerprint"].lower() == fingerprint)), None)
    if not key:
        raise FlashError("Failed to import key")
    if (key.get("algo") == "1") and (int(key.get("length", "0")) < 2048):
        # https://infra.apache.org/release-signing.html#note
        # Says that keys must be at least 2048 bits
        raise FlashError("Key is not long enough; must be at least 2048 bits")

    # Store key in database
    async with get_session() as db_session:
        return await key_user_session_add(session, public_key, key, selected_pmcs, db_session)


async def key_user_session_add(
    session: ClientSession,
    public_key: str,
    key: dict,
    selected_pmcs: list[str],
    db_session: AsyncSession,
) -> dict | None:
    # Check if key already exists
    statement = select(PublicSigningKey).where(PublicSigningKey.apache_uid == session.uid)

    # # If uncommented, this will prevent a user from adding a second key
    # existing_key = (await db_session.execute(statement)).scalar_one_or_none()
    # if existing_key:
    #     return ("You already have a key registered", None)

    if not session.uid:
        raise FlashError("You must be signed in to add a key")

    fingerprint = key.get("fingerprint")
    if not isinstance(fingerprint, str):
        raise FlashError("Invalid key fingerprint")
    fingerprint = fingerprint.lower()
    uids = key.get("uids")
    async with db_session.begin():
        # Create new key record
        key_record = PublicSigningKey(
            fingerprint=fingerprint,
            algorithm=int(key["algo"]),
            length=int(key.get("length", "0")),
            created=datetime.datetime.fromtimestamp(int(key["date"])),
            expires=datetime.datetime.fromtimestamp(int(key["expires"])) if key.get("expires") else None,
            declared_uid=uids[0] if uids else None,
            apache_uid=session.uid,
            ascii_armored_key=public_key,
        )
        db_session.add(key_record)

        # Link key to selected PMCs
        for pmc_name in selected_pmcs:
            statement = select(PMC).where(PMC.project_name == pmc_name)
            pmc = (await db_session.execute(statement)).scalar_one_or_none()
            if pmc and pmc.id:
                link = PMCKeyLink(pmc_id=pmc.id, key_fingerprint=key_record.fingerprint)
                db_session.add(link)
            else:
                # TODO: Log? Add to "error"?
                continue

    return {
        "key_id": key["keyid"],
        "fingerprint": key["fingerprint"].lower() if key.get("fingerprint") else "Unknown",
        "user_id": key["uids"][0] if key.get("uids") else "Unknown",
        "creation_date": datetime.datetime.fromtimestamp(int(key["date"])),
        "expiration_date": datetime.datetime.fromtimestamp(int(key["expires"])) if key.get("expires") else None,
        "data": pprint.pformat(key),
    }


# Package functions


async def package_add_artifact_info_get(
    db_session: AsyncSession, uploads_path: Path, artifact_file: FileStorage
) -> tuple[str, str, int]:
    """Get artifact information during package addition process.

    Returns a tuple of (sha3_hash, sha512_hash, size) for the artifact file.
    Validates that the artifact hasn't already been uploaded to another release.
    """
    # In a separate function to appease the complexity checker
    artifact_sha3, artifact_size = await file_hash_save(uploads_path, artifact_file)

    # Check for duplicates by artifact_sha3 before proceeding
    statement = select(Package).where(Package.artifact_sha3 == artifact_sha3)
    duplicate = (await db_session.execute(statement)).first()
    if duplicate:
        # Remove the saved file since we won't be using it
        await aiofiles.os.remove(uploads_path / artifact_sha3)
        raise FlashError("This exact file has already been uploaded to another release")

    # Compute SHA-512 of the artifact for the package record
    return artifact_sha3, compute_sha512(uploads_path / artifact_sha3), artifact_size


async def package_add_post(session: ClientSession, request: Request) -> Response:
    """Handle POST request for adding a package to a release."""
    try:
        release_key, artifact_file, checksum_file, signature_file, artifact_type = await package_add_validate(request)
    except FlashError as e:
        await flash(f"{e!s}", "error")
        return redirect(url_for("root_package_add"))
    # This must come here to appease the type checker
    if artifact_file.filename is None:
        await flash("Release artifact filename is required", "error")
        return redirect(url_for("root_package_add"))

    # Save files and create package record in one transaction
    async with get_session() as db_session:
        async with db_session.begin():
            # Process and save the files
            try:
                try:
                    artifact_sha3, artifact_size, artifact_sha512, signature_sha3 = await package_add_session_process(
                        db_session, release_key, artifact_file, checksum_file, signature_file
                    )
                except FlashError as e:
                    await flash(f"{e!s}", "error")
                    return redirect(url_for("root_package_add"))

                # Create the package record
                package = Package(
                    artifact_sha3=artifact_sha3,
                    artifact_type=artifact_type,
                    filename=artifact_file.filename,
                    signature_sha3=signature_sha3,
                    sha512=artifact_sha512,
                    release_key=release_key,
                    uploaded=datetime.datetime.now(datetime.UTC),
                    bytes_size=artifact_size,
                )
                db_session.add(package)

            except Exception as e:
                await flash(f"Error processing files: {e!s}", "error")
                return redirect(url_for("root_package_add"))

    # Otherwise redirect to review page
    return redirect(url_for("root_candidate_review"))


async def package_add_session_process(
    db_session: AsyncSession,
    release_key: str,
    artifact_file: FileStorage,
    checksum_file: FileStorage | None,
    signature_file: FileStorage | None,
) -> tuple[str, int, str, str | None]:
    """Helper function for package_add_post."""

    # First check for duplicates by filename
    statement = select(Package).where(
        Package.release_key == release_key,
        Package.filename == artifact_file.filename,
    )
    duplicate = (await db_session.execute(statement)).first()

    if duplicate:
        raise FlashError("This release artifact has already been uploaded")

    # Save files using their hashes as filenames
    uploads_path = Path(get_release_storage_dir())
    try:
        artifact_sha3, artifact_sha512, artifact_size = await package_add_artifact_info_get(
            db_session, uploads_path, artifact_file
        )
    except Exception as e:
        raise FlashError(f"Error saving artifact file: {e!s}")
    # Note: "error" is not permitted past this point
    # Because we don't want to roll back saving the artifact

    # Validate checksum file if provided
    if checksum_file:
        try:
            # Read only the number of bytes required for the checksum
            bytes_required: int = len(artifact_sha512)
            checksum_content = checksum_file.read(bytes_required).decode().strip()
            if checksum_content.lower() != artifact_sha512.lower():
                await flash("Warning: Provided checksum does not match computed SHA-512", "warning")
        except UnicodeDecodeError:
            await flash("Warning: Could not read checksum file as text", "warning")
        except Exception as e:
            await flash(f"Warning: Error validating checksum file: {e!s}", "warning")

    # Process signature file if provided
    signature_sha3 = None
    if signature_file and signature_file.filename:
        if not signature_file.filename.endswith(".asc"):
            await flash("Warning: Signature file should have .asc extension", "warning")
        try:
            signature_sha3, _ = await file_hash_save(uploads_path, signature_file)
        except Exception as e:
            await flash(f"Warning: Could not save signature file: {e!s}", "warning")

    return artifact_sha3, artifact_size, artifact_sha512, signature_sha3


async def package_add_validate(
    request: Request,
) -> tuple[str, FileStorage, FileStorage | None, FileStorage | None, str]:
    # This calls quart.wrappers.request.form _load_form_data
    # Which calls quart.formparser parse and parse_func and parser.parse
    # Which calls _write which calls tempfile, which is synchronous
    # It's getting a tempfile back from some prior call
    form = await request.form

    # TODO: Check that the submitter is a committer of the project

    release_key = form.get("release_key")
    if (not release_key) or (not isinstance(release_key, str)):
        raise FlashError("Release key is required")

    # Get all uploaded files
    files = await request.files
    artifact_file = files.get("release_artifact")
    checksum_file = files.get("release_checksum")
    signature_file = files.get("release_signature")
    if not isinstance(artifact_file, FileStorage):
        raise FlashError("Release artifact file is required")
    if checksum_file is not None and not isinstance(checksum_file, FileStorage):
        raise FlashError("Problem with checksum file")
    if signature_file is not None and not isinstance(signature_file, FileStorage):
        raise FlashError("Problem with signature file")

    # Get and validate artifact type
    artifact_type = form.get("artifact_type")
    if (not artifact_type) or (not isinstance(artifact_type, str)):
        raise FlashError("Artifact type is required")
    if artifact_type not in ["source", "binary", "reproducible"]:
        raise FlashError("Invalid artifact type")

    return release_key, artifact_file, checksum_file, signature_file, artifact_type


async def package_data_get(db_session: AsyncSession, artifact_sha3: str, release_key: str, session_uid: str) -> Package:
    """Validate package deletion request and return the package if valid."""
    # Get the package and its associated release
    if Package.release is None:
        raise FlashError("Package has no associated release")
    if Release.pmc is None:
        raise FlashError("Release has no associated PMC")

    pkg_release = cast(InstrumentedAttribute[Release], Package.release)
    rel_pmc = cast(InstrumentedAttribute[PMC], Release.pmc)
    statement = (
        select(Package)
        .options(selectinload(pkg_release).selectinload(rel_pmc))
        .where(Package.artifact_sha3 == artifact_sha3)
    )
    result = await db_session.execute(statement)
    package = result.scalar_one_or_none()

    if not package:
        raise FlashError("Package not found")

    if package.release_key != release_key:
        raise FlashError("Invalid release key")

    # Check permissions
    if package.release and package.release.pmc:
        if session_uid not in package.release.pmc.pmc_members and session_uid not in package.release.pmc.committers:
            raise FlashError("You don't have permission to access this package")

    return package


async def package_files_delete(package: Package, uploads_path: Path) -> None:
    """Delete the artifact and signature files associated with a package."""
    if package.artifact_sha3:
        artifact_path = uploads_path / package.artifact_sha3
        if await aiofiles.os.path.exists(artifact_path):
            await aiofiles.os.remove(artifact_path)

    if package.signature_sha3:
        signature_path = uploads_path / package.signature_sha3
        if await aiofiles.os.path.exists(signature_path):
            await aiofiles.os.remove(signature_path)


# Release functions


async def release_add_post(session: ClientSession, request: Request) -> Response:
    """Handle POST request for creating a new release."""
    form = await request.form

    project_name = form.get("project_name")
    if not project_name:
        raise ASFQuartException("Project name is required", errorcode=400)

    product_name = form.get("product_name")
    if not product_name:
        raise ASFQuartException("Product name is required", errorcode=400)

    version = form.get("version")
    if not version:
        raise ASFQuartException("Version is required", errorcode=400)

    # TODO: Forbid creating a release with an existing project, product, and version
    # Create the release record in the database
    async with get_session() as db_session:
        async with db_session.begin():
            statement = select(PMC).where(PMC.project_name == project_name)
            pmc = (await db_session.execute(statement)).scalar_one_or_none()
            if not pmc:
                APP.logger.error(f"PMC not found for project {project_name}")
                APP.logger.debug(f"Available committees: {session.committees}")
                APP.logger.debug(f"Available projects: {session.projects}")
                raise ASFQuartException("PMC not found", errorcode=404)

            # Verify user is a PMC member or committer of the project
            # We use pmc.display_name, so this must come within the transaction
            if project_name not in session.committees and project_name not in session.projects:
                raise ASFQuartException(
                    f"You must be a PMC member or committer of {pmc.display_name} to submit a release candidate",
                    errorcode=403,
                )

            # Generate a 128-bit random token for the release storage key
            # TODO: Perhaps we should call this the release_key instead
            storage_key = secrets.token_hex(16)

            # Create or get existing product line
            statement = select(ProductLine).where(
                ProductLine.pmc_id == pmc.id, ProductLine.product_name == product_name
            )
            product_line = (await db_session.execute(statement)).scalar_one_or_none()

            if not product_line:
                # Create new product line if it doesn't exist
                product_line = ProductLine(pmc_id=pmc.id, product_name=product_name, latest_version=version)
                db_session.add(product_line)
                # Flush to get the product_line.id
                await db_session.flush()

            # Create release record with product line
            release = Release(
                storage_key=storage_key,
                stage=ReleaseStage.CANDIDATE,
                phase=ReleasePhase.RELEASE_CANDIDATE,
                pmc_id=pmc.id,
                product_line_id=product_line.id,
                version=version,
                created=datetime.datetime.now(datetime.UTC),
            )
            db_session.add(release)

    # Redirect to the add package page with the storage token
    return redirect(url_for("root_package_add", storage_key=storage_key))


async def release_delete_validate(db_session: AsyncSession, release_key: str, session_uid: str) -> Release:
    """Validate release deletion request and return the release if valid."""
    if Release.pmc is None:
        raise FlashError("Release has no associated PMC")

    rel_pmc = cast(InstrumentedAttribute[PMC], Release.pmc)
    statement = select(Release).options(selectinload(rel_pmc)).where(Release.storage_key == release_key)
    result = await db_session.execute(statement)
    release = result.scalar_one_or_none()

    if not release:
        raise FlashError("Release not found")

    # Check permissions
    if release.pmc:
        if session_uid not in release.pmc.pmc_members and session_uid not in release.pmc.committers:
            raise FlashError("You don't have permission to delete this release")

    return release


async def release_files_delete(release: Release, uploads_path: Path) -> None:
    """Delete all files associated with a release."""
    if not release.packages:
        return

    for package in release.packages:
        await package_files_delete(package, uploads_path)


# Root functions


@app_route("/")
async def root() -> str:
    """Main page."""
    return await render_template("index.html")


@app_route("/candidate/create", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_candidate_create() -> Response | str:
    """Create a new release in the database."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    # For POST requests, handle the release creation
    if request.method == "POST":
        return await release_add_post(session, request)

    # Get PMC objects for all projects the user is a member of
    async with get_session() as db_session:
        from sqlalchemy.sql.expression import ColumnElement

        project_list = session.committees + session.projects
        project_name: ColumnElement[str] = cast(ColumnElement[str], PMC.project_name)
        statement = select(PMC).where(project_name.in_(project_list))
        user_pmcs = (await db_session.execute(statement)).scalars().all()

    # For GET requests, show the form
    return await render_template(
        "candidate-create.html",
        asf_id=session.uid,
        user_pmcs=user_pmcs,
    )


@app_route("/candidate/review")
@require(Requirements.committer)
async def root_candidate_review() -> str:
    """Show all release candidates to which the user has access."""
    # time.sleep(0.37)
    # await asyncio.sleep(0.73)
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    async with get_session() as db_session:
        # Get all releases where the user is a PMC member or committer
        # TODO: We don't actually record who uploaded the release candidate
        # We should probably add that information!
        # TODO: This duplicates code in root_package_add
        release_pmc = selectinload(cast(InstrumentedAttribute[PMC], Release.pmc))
        release_packages = selectinload(cast(InstrumentedAttribute[list[Package]], Release.packages))
        package_tasks = selectinload(cast(InstrumentedAttribute[list[Package]], Release.packages)).selectinload(
            cast(InstrumentedAttribute[list[Task]], Package.tasks)
        )
        release_product_line = selectinload(cast(InstrumentedAttribute[ProductLine], Release.product_line))
        statement = (
            select(Release)
            .options(release_pmc, release_packages, package_tasks, release_product_line)
            .join(PMC)
            .where(Release.stage == ReleaseStage.CANDIDATE)
        )
        releases = (await db_session.execute(statement)).scalars().all()

        # Filter to only show releases for PMCs or PPMCs where the user is a member or committer
        user_releases = []
        for r in releases:
            if r.pmc is None:
                continue
            # For PPMCs the "members" are stored in the committers field
            if session.uid in r.pmc.pmc_members or session.uid in r.pmc.committers:
                user_releases.append(r)

        # time.sleep(0.37)
        # await asyncio.sleep(0.73)
        return await render_template(
            "candidate-review.html",
            releases=user_releases,
            format_file_size=format_file_size,
            format_artifact_name=format_artifact_name,
        )


@app_route("/docs/verify/<filename>")
@require(Requirements.committer)
async def root_docs_verify(filename: str) -> str:
    """Show verification instructions for an artifact."""
    # Get query parameters
    artifact_sha3 = request.args.get("artifact_sha3", "")
    sha512 = request.args.get("sha512", "")
    has_signature = request.args.get("has_signature", "false").lower() == "true"

    # Return the template
    return await render_template(
        "docs-verify.html",
        filename=filename,
        artifact_sha3=artifact_sha3,
        sha512=sha512,
        has_signature=has_signature,
    )


@app_route("/download/<release_key>/<artifact_sha3>")
@require(Requirements.committer)
async def root_download_artifact(release_key: str, artifact_sha3: str) -> Response | QuartResponse:
    """Download an artifact file."""
    # TODO: This function is very similar to the signature download function
    # We should probably extract the common code into a helper function
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    async with get_session() as db_session:
        # Find the package
        release_pmc = selectinload(cast(InstrumentedAttribute[Release], Package.release)).selectinload(
            cast(InstrumentedAttribute[PMC], Release.pmc)
        )
        statement = (
            select(Package)
            .where(Package.artifact_sha3 == artifact_sha3, Package.release_key == release_key)
            .options(release_pmc)
        )
        result = await db_session.execute(statement)
        package = result.scalar_one_or_none()

        if not package:
            await flash("Artifact not found", "error")
            return redirect(url_for("root_candidate_review"))

        # Check permissions
        if package.release and package.release.pmc:
            if (session.uid not in package.release.pmc.pmc_members) and (
                session.uid not in package.release.pmc.committers
            ):
                await flash("You don't have permission to download this file", "error")
                return redirect(url_for("root_candidate_review"))

        # Construct file path
        file_path = Path(get_release_storage_dir()) / artifact_sha3

        # Check that the file exists
        if not await aiofiles.os.path.exists(file_path):
            await flash("Artifact file not found", "error")
            return redirect(url_for("root_candidate_review"))

        # Send the file with original filename
        return await send_file(
            file_path, as_attachment=True, attachment_filename=package.filename, mimetype="application/octet-stream"
        )


@app_route("/download/signature/<release_key>/<signature_sha3>")
@require(Requirements.committer)
async def root_download_signature(release_key: str, signature_sha3: str) -> QuartResponse | Response:
    """Download a signature file."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    async with get_session() as db_session:
        # Find the package that has this signature
        release_pmc = selectinload(cast(InstrumentedAttribute[Release], Package.release)).selectinload(
            cast(InstrumentedAttribute[PMC], Release.pmc)
        )
        statement = (
            select(Package)
            .where(Package.signature_sha3 == signature_sha3, Package.release_key == release_key)
            .options(release_pmc)
        )
        result = await db_session.execute(statement)
        package = result.scalar_one_or_none()

        if not package:
            await flash("Signature not found", "error")
            return redirect(url_for("root_candidate_review"))

        # Check permissions
        if package.release and package.release.pmc:
            if (session.uid not in package.release.pmc.pmc_members) and (
                session.uid not in package.release.pmc.committers
            ):
                await flash("You don't have permission to download this file", "error")
                return redirect(url_for("root_candidate_review"))

        # Construct file path
        file_path = Path(get_release_storage_dir()) / signature_sha3

        # Check that the file exists
        if not await aiofiles.os.path.exists(file_path):
            await flash("Signature file not found", "error")
            return redirect(url_for("root_candidate_review"))

        # Send the file with original filename and .asc extension
        return await send_file(
            file_path,
            as_attachment=True,
            attachment_filename=f"{package.filename}.asc",
            mimetype="application/pgp-signature",
        )


@app_route("/keys/add", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_keys_add() -> str:
    """Add a new public signing key to the user's account."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    key_info = None

    # Get PMC objects for all projects the user is a member of
    async with get_session() as db_session:
        from sqlalchemy.sql.expression import ColumnElement

        project_list = session.committees + session.projects
        project_name = cast(ColumnElement[str], PMC.project_name)
        statement = select(PMC).where(project_name.in_(project_list))
        user_pmcs = (await db_session.execute(statement)).scalars().all()

    if request.method == "POST":
        try:
            key_info = await key_add_post(session, request, user_pmcs)
        except FlashError as e:
            await flash(str(e), "error")
        except Exception as e:
            await flash(f"Exception: {e}", "error")

    return await render_template(
        "keys-add.html",
        asf_id=session.uid,
        user_pmcs=user_pmcs,
        key_info=key_info,
        algorithms=algorithms,
    )


@app_route("/keys/delete", methods=["POST"])
@require(Requirements.committer)
async def root_keys_delete() -> Response:
    """Delete a public signing key from the user's account."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    form = await request.form
    fingerprint = form.get("fingerprint")
    if not fingerprint:
        await flash("No key fingerprint provided", "error")
        return redirect(url_for("root_keys_review"))

    async with get_session() as db_session:
        async with db_session.begin():
            # Get the key and verify ownership
            statement = select(PublicSigningKey).where(
                PublicSigningKey.fingerprint == fingerprint, PublicSigningKey.apache_uid == session.uid
            )
            key = (await db_session.execute(statement)).scalar_one_or_none()

            if not key:
                await flash("Key not found or not owned by you", "error")
                return redirect(url_for("root_keys_review"))

            # Delete the key
            await db_session.delete(key)

    await flash("Key deleted successfully", "success")
    return redirect(url_for("root_keys_review"))


@app_route("/keys/review")
@require(Requirements.committer)
async def root_keys_review() -> str:
    """Show all keys associated with the user's account."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    # Get all existing keys for the user
    async with get_session() as db_session:
        pmcs_loader = selectinload(cast(InstrumentedAttribute[list[PMC]], PublicSigningKey.pmcs))
        statement = select(PublicSigningKey).options(pmcs_loader).where(PublicSigningKey.apache_uid == session.uid)
        user_keys = (await db_session.execute(statement)).scalars().all()

    status_message = request.args.get("status_message")
    status_type = request.args.get("status_type")

    return await render_template(
        "keys-review.html",
        asf_id=session.uid,
        user_keys=user_keys,
        algorithms=algorithms,
        status_message=status_message,
        status_type=status_type,
        now=datetime.datetime.now(datetime.UTC),
    )


@app_route("/package/add", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_package_add() -> Response | str:
    """Add package artifacts to an existing release."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    # For POST requests, handle the file upload
    if request.method == "POST":
        return await package_add_post(session, request)

    # Get the storage_key from the query parameters (if redirected from create)
    storage_key = request.args.get("storage_key")

    # Get all releases where the user is a PMC member or committer of the associated PMC
    async with get_session() as db_session:
        # TODO: This duplicates code in root_candidate_review
        release_pmc = selectinload(cast(InstrumentedAttribute[PMC], Release.pmc))
        release_product_line = selectinload(cast(InstrumentedAttribute[ProductLine], Release.product_line))
        statement = (
            select(Release)
            .options(release_pmc, release_product_line)
            .join(PMC)
            .where(Release.stage == ReleaseStage.CANDIDATE)
        )
        releases = (await db_session.execute(statement)).scalars().all()

        # Filter to only show releases for PMCs or PPMCs where the user is a member or committer
        # Can we do this in sqlmodel using JSON container operators?
        user_releases = []
        for r in releases:
            if r.pmc is None:
                continue
            # For PPMCs the "members" are stored in the committers field
            if session.uid in r.pmc.pmc_members or session.uid in r.pmc.committers:
                user_releases.append(r)

    # For GET requests, show the form
    return await render_template(
        "package-add.html",
        asf_id=session.uid,
        releases=user_releases,
        selected_release=storage_key,
    )


@app_route("/package/check", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_package_check() -> str | Response:
    """Show or create package verification tasks."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    # Get parameters from either form data (POST) or query args (GET)
    if request.method == "POST":
        form = await request.form
        artifact_sha3 = form.get("artifact_sha3")
        release_key = form.get("release_key")
    else:
        artifact_sha3 = request.args.get("artifact_sha3")
        release_key = request.args.get("release_key")

    if not artifact_sha3 or not release_key:
        await flash("Missing required parameters", "error")
        return redirect(url_for("root_candidate_review"))

    async with get_session() as db_session:
        async with db_session.begin():
            # Get the package and verify permissions
            try:
                package = await package_data_get(db_session, artifact_sha3, release_key, session.uid)
            except FlashError as e:
                await flash(str(e), "error")
                return redirect(url_for("root_candidate_review"))

            if request.method == "POST":
                # Check if package already has active tasks
                tasks, has_active_tasks = await task_package_status_get(db_session, artifact_sha3)
                if has_active_tasks:
                    await flash("Package verification is already in progress", "warning")
                    return redirect(url_for("root_candidate_review"))

                try:
                    await task_verification_create(db_session, package)
                except FlashError as e:
                    await flash(str(e), "error")
                    return redirect(url_for("root_candidate_review"))

                await flash(f"Added verification tasks for package {package.filename}", "success")
                return redirect(url_for("root_package_check", artifact_sha3=artifact_sha3, release_key=release_key))
            else:
                # Get all tasks for this package for GET request
                tasks, _ = await task_package_status_get(db_session, artifact_sha3)
                all_tasks_completed = bool(tasks) and all(
                    task.status == TaskStatus.COMPLETED or task.status == TaskStatus.FAILED for task in tasks
                )
                return await render_template(
                    "package-check.html",
                    package=package,
                    release=package.release,
                    tasks=tasks,
                    all_tasks_completed=all_tasks_completed,
                    format_file_size=format_file_size,
                )


@app_route("/package/check/restart", methods=["POST"])
@require(Requirements.committer)
async def root_package_check_restart() -> Response:
    """Restart package verification tasks."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    form = await request.form
    artifact_sha3 = form.get("artifact_sha3")
    release_key = form.get("release_key")

    if not artifact_sha3 or not release_key:
        await flash("Missing required parameters", "error")
        return redirect(url_for("root_candidate_review"))

    async with get_session() as db_session:
        async with db_session.begin():
            # Get the package and verify permissions
            try:
                package = await package_data_get(db_session, artifact_sha3, release_key, session.uid)
            except FlashError as e:
                await flash(str(e), "error")
                return redirect(url_for("root_candidate_review"))

            # Check if package has any active tasks
            tasks, has_active_tasks = await task_package_status_get(db_session, artifact_sha3)
            if has_active_tasks:
                await flash("Cannot restart checks while tasks are still in progress", "error")
                return redirect(url_for("root_package_check", artifact_sha3=artifact_sha3, release_key=release_key))

            # Delete existing tasks
            for task in tasks:
                await db_session.delete(task)

            try:
                await task_verification_create(db_session, package)
            except FlashError as e:
                await flash(str(e), "error")
                return redirect(url_for("root_candidate_review"))

            await flash("Package checks restarted successfully", "success")
            return redirect(url_for("root_package_check", artifact_sha3=artifact_sha3, release_key=release_key))


@app_route("/package/delete", methods=["POST"])
@require(Requirements.committer)
async def root_package_delete() -> Response:
    """Delete a package from a release candidate."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    form = await request.form
    artifact_sha3 = form.get("artifact_sha3")
    release_key = form.get("release_key")

    if not artifact_sha3 or not release_key:
        await flash("Missing required parameters", "error")
        return redirect(url_for("root_candidate_review"))

    async with get_session() as db_session:
        async with db_session.begin():
            try:
                package = await package_data_get(db_session, artifact_sha3, release_key, session.uid)
                await package_files_delete(package, Path(get_release_storage_dir()))
                await db_session.delete(package)
            except FlashError as e:
                await flash(str(e), "error")
                return redirect(url_for("root_candidate_review"))
            except Exception as e:
                await flash(f"Error deleting files: {e!s}", "error")
                return redirect(url_for("root_candidate_review"))

    await flash("Package deleted successfully", "success")
    return redirect(url_for("root_candidate_review"))


@app_route("/project/directory")
async def root_project_directory() -> str:
    """Main project directory page."""
    projects = await get_pmcs()
    return await render_template("project-directory.html", projects=projects)


@app_route("/project/list")
async def root_project_list() -> list[dict]:
    """List all projects in the database."""
    pmcs = await get_pmcs()

    return [
        {
            "id": pmc.id,
            "project_name": pmc.project_name,
            "pmc_members": pmc.pmc_members,
            "committers": pmc.committers,
            "release_managers": pmc.release_managers,
        }
        for pmc in pmcs
    ]


@app_route("/project/<project_name>")
async def root_project_project_name(project_name: str) -> dict:
    """Get a specific project by project name."""
    pmc = await get_pmc_by_name(project_name)
    if not pmc:
        raise ASFQuartException("PMC not found", errorcode=404)

    return {
        "id": pmc.id,
        "project_name": pmc.project_name,
        "pmc_members": pmc.pmc_members,
        "committers": pmc.committers,
        "release_managers": pmc.release_managers,
    }


@app_route("/release/delete", methods=["POST"])
@require(Requirements.committer)
async def root_release_delete() -> Response:
    """Delete a release and all its associated packages."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    form = await request.form
    release_key = form.get("release_key")

    if not release_key:
        await flash("Missing required parameters", "error")
        return redirect(url_for("root_candidate_review"))

    async with get_session() as db_session:
        async with db_session.begin():
            try:
                release = await release_delete_validate(db_session, release_key, session.uid)
                await release_files_delete(release, Path(get_release_storage_dir()))
                await db_session.delete(release)
            except FlashError as e:
                await flash(str(e), "error")
                return redirect(url_for("root_candidate_review"))
            except Exception as e:
                await flash(f"Error deleting release: {e!s}", "error")
                return redirect(url_for("root_candidate_review"))

    await flash("Release deleted successfully", "success")
    return redirect(url_for("root_candidate_review"))


async def task_package_status_get(db_session: AsyncSession, artifact_sha3: str) -> tuple[Sequence[Task], bool]:
    """
    Get all tasks for a package and determine if any are still in progress.
    Returns tuple[Sequence[Task], bool]: List of tasks and whether any are still in progress
    TODO: Could instead give active count and total count
    """
    statement = select(Task).where(Task.package_sha3 == artifact_sha3)
    tasks = (await db_session.execute(statement)).scalars().all()
    has_active_tasks = any(task.status in [TaskStatus.QUEUED, TaskStatus.ACTIVE] for task in tasks)
    return tasks, has_active_tasks


async def task_verification_create(db_session: AsyncSession, package: Package) -> list[Task]:
    """Create verification tasks for a package."""
    if not package.release or not package.release.pmc:
        raise FlashError("Could not determine PMC for package")

    if package.signature_sha3 is None:
        raise FlashError("Package has no signature")

    # TODO: We should probably use an enum for task_type
    tasks = [
        Task(
            status=TaskStatus.QUEUED,
            task_type="verify_archive_integrity",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
        Task(
            status=TaskStatus.QUEUED,
            task_type="verify_archive_structure",
            task_args=["releases/" + package.artifact_sha3, package.filename],
            package_sha3=package.artifact_sha3,
        ),
        Task(
            status=TaskStatus.QUEUED,
            task_type="verify_signature",
            task_args=[
                package.release.pmc.project_name,
                "releases/" + package.artifact_sha3,
                "releases/" + package.signature_sha3,
            ],
            package_sha3=package.artifact_sha3,
        ),
        Task(
            status=TaskStatus.QUEUED,
            task_type="verify_license_files",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
        Task(
            status=TaskStatus.QUEUED,
            task_type="verify_license_headers",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
        Task(
            status=TaskStatus.QUEUED,
            task_type="verify_rat_license",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
        # Task(
        #     status=TaskStatus.QUEUED,
        #     task_type="generate_spdx_sbom",
        #     task_args=["releases/" + package.artifact_sha3],
        #     package_sha3=package.artifact_sha3,
        # ),
        Task(
            status=TaskStatus.QUEUED,
            task_type="generate_cyclonedx_sbom",
            task_args=["releases/" + package.artifact_sha3],
            package_sha3=package.artifact_sha3,
        ),
    ]
    for task in tasks:
        db_session.add(task)

    return tasks
