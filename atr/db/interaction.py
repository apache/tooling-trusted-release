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
import contextlib
import datetime
import logging
import pathlib
import pprint
import re
from collections.abc import AsyncGenerator
from typing import Final

import aiofiles.os
import aioshutil
import asfquart.base as base
import quart
import sqlalchemy
import sqlmodel

import atr.analysis as analysis
import atr.db as db
import atr.db.models as models
import atr.schema as schema
import atr.user as user
import atr.util as util

_LOGGER: Final = logging.getLogger(__name__)


class ApacheUserMissingError(RuntimeError):
    def __init__(self, message: str, fingerprint: str | None, primary_uid: str | None) -> None:
        super().__init__(message)
        self.fingerprint = fingerprint
        self.primary_uid = primary_uid


class InteractionError(RuntimeError):
    pass


class PublicKeyError(RuntimeError):
    pass


class PathInfo(schema.Strict):
    artifacts: set[pathlib.Path] = schema.factory(set)
    errors: dict[pathlib.Path, list[models.CheckResult]] = schema.factory(dict)
    metadata: set[pathlib.Path] = schema.factory(set)
    successes: dict[pathlib.Path, list[models.CheckResult]] = schema.factory(dict)
    warnings: dict[pathlib.Path, list[models.CheckResult]] = schema.factory(dict)


def ensure_session(caller_data: db.Session | None) -> db.Session | contextlib.nullcontext[db.Session]:
    if caller_data is None:
        return db.session()
    return contextlib.nullcontext(caller_data)


@contextlib.asynccontextmanager
async def ephemeral_gpg_home() -> AsyncGenerator[str]:
    """Create a temporary directory for an isolated GPG home, and clean it up on exit."""
    async with util.async_temporary_directory(prefix="gpg-") as temp_dir:
        yield str(temp_dir)


async def has_failing_checks(
    release: models.Release, revision_number: str, caller_data: db.Session | None = None
) -> bool:
    async with ensure_session(caller_data) as data:
        query = (
            sqlmodel.select(sqlalchemy.func.count())
            .select_from(models.CheckResult)
            .where(
                models.CheckResult.release_name == release.name,
                models.CheckResult.revision_number == revision_number,
                models.CheckResult.status == models.CheckResultStatus.FAILURE,
            )
        )
        result = await data.execute(query)
        return result.scalar_one() > 0


async def key_user_add(
    session_asf_uid: str | None,
    public_key: str,
    selected_committees: list[str],
    ldap_data: dict[str, str] | None = None,
    update_existing: bool = False,
) -> list[dict]:
    session_asf_uid = session_asf_uid.lower() if session_asf_uid else None
    if not public_key:
        raise PublicKeyError("Public key is required")

    # Validate the key using GPG and get its properties
    # This does not add it to the database, only validates and gets its properties
    keys = await _key_user_add_validate_key_properties(public_key)

    added_keys = []
    for key in keys:
        uids = key.get("uids", [])
        asf_uid = await util.asf_uid_from_uids(uids, ldap_data=ldap_data)
        test_key_uids = ["Apache Tooling (For test use only) <apache-tooling@example.invalid>"]
        is_admin = user.is_admin(session_asf_uid)
        if (uids == test_key_uids) and is_admin:
            # Allow the test key
            # TODO: We should fix the test key, not add an exception for it
            # But the admin check probably makes this safe enough
            asf_uid = session_asf_uid
        elif session_asf_uid and (asf_uid != session_asf_uid):
            # TODO: Give a more detailed error message about why and what to do
            raise InteractionError(f"Key {key.get('fingerprint', '').upper()} is not associated with your ASF account")
        async with db.session() as data:
            # Store the key in the database
            added = await key_user_session_add(
                asf_uid, public_key, key, selected_committees, data, update_existing=update_existing
            )
            if added:
                added_keys.append(added)
            else:
                _LOGGER.warning(f"Failed to add key {key} to user {asf_uid}")
    return added_keys


async def key_user_session_add(
    asf_uid: str | None,
    public_key: str,
    key: dict,
    selected_committees: list[str],
    data: db.Session,
    update_existing: bool = False,
) -> dict | None:
    # TODO: Check if key already exists
    # psk_statement = select(PublicSigningKey).where(PublicSigningKey.apache_uid == session.uid)

    # # If uncommented, this will prevent a user from adding a second key
    # existing_key = (await db_session.execute(statement)).scalar_one_or_none()
    # if existing_key:
    #     return ("You already have a key registered", None)

    fingerprint = key.get("fingerprint")
    # for subkey in key.get("subkeys", []):
    #     if subkey[1] == "s":
    #         # It's a signing key, so use its fingerprint instead
    #         # TODO: Not sure that we should do this
    #         # TODO: Check for multiple signing subkeys
    #         fingerprint = subkey[2]
    #         break
    if not isinstance(fingerprint, str):
        raise RuntimeError("Invalid key fingerprint")
    fingerprint = fingerprint.lower()
    uids = key.get("uids", [])
    key_record: models.PublicSigningKey | None = None

    latest_self_signature = _key_latest_self_signature(key)
    created = datetime.datetime.fromtimestamp(int(key["date"]), tz=datetime.UTC)
    expires = datetime.datetime.fromtimestamp(int(key["expires"]), tz=datetime.UTC) if key.get("expires") else None

    async with data.begin():
        existing = await data.public_signing_key(fingerprint=fingerprint).get()
        # TODO: This can race
        if existing:
            update = update_existing
            # If the new key has a latest self signature
            if latest_self_signature is not None:
                # And the self signature is newer, update it
                if (existing.latest_self_signature is None) or (existing.latest_self_signature < latest_self_signature):
                    update = True
            if update:
                existing.fingerprint = fingerprint
                existing.algorithm = int(key["algo"])
                existing.length = int(key.get("length", "0"))
                existing.created = created
                existing.latest_self_signature = latest_self_signature
                existing.expires = expires
                existing.primary_declared_uid = uids[0] if uids else None
                existing.secondary_declared_uids = uids[1:]
                existing.apache_uid = asf_uid.lower() if asf_uid else None
                existing.ascii_armored_key = (
                    public_key.decode("utf-8", errors="replace") if isinstance(public_key, bytes) else public_key
                )
                logging.info(f"Found existing key {fingerprint.upper()}, updating associations")
            else:
                logging.info(f"Found existing key {fingerprint.upper()}, no update needed")
            key_record = existing
        else:
            # Key doesn't exist, create it
            logging.info(f"Adding new key {fingerprint.upper()}")

            key_record = models.PublicSigningKey(
                fingerprint=fingerprint,
                algorithm=int(key["algo"]),
                length=int(key.get("length", "0")),
                created=created,
                latest_self_signature=latest_self_signature,
                expires=expires,
                primary_declared_uid=uids[0] if uids else None,
                secondary_declared_uids=uids[1:],
                apache_uid=asf_uid.lower() if asf_uid else None,
                ascii_armored_key=public_key,
            )
            data.add(key_record)
            await data.flush()
            await data.refresh(key_record)

        # Link key to selected PMCs and track status for each
        committee_statuses: dict[str, str] = {}
        for committee_name in selected_committees:
            committee = await data.committee(name=committee_name).get()
            if committee and committee.name:
                # Check whether the link already exists
                link_exists = await data.execute(
                    sqlmodel.select(models.KeyLink).where(
                        models.KeyLink.committee_name == committee.name,
                        models.KeyLink.key_fingerprint == key_record.fingerprint,
                    )
                )
                if link_exists.scalar_one_or_none() is None:
                    committee_statuses[committee_name] = "newly_linked"
                    # Link doesn't exist, create it
                    logging.debug(f"Linking key {fingerprint.upper()} to committee {committee_name}")
                    link = models.KeyLink(committee_name=committee.name, key_fingerprint=key_record.fingerprint)
                    data.add(link)
                else:
                    committee_statuses[committee_name] = "already_linked"
                    logging.debug(f"Link already exists for key {fingerprint.upper()} and committee {committee_name}")
            else:
                logging.warning(f"Could not find committee {committee_name} to link key {fingerprint.upper()}")
                continue

    # TODO: What if there is no email?
    user_id_str = key_record.primary_declared_uid or ""
    email = util.email_from_uid(user_id_str) or ""

    return {
        "key_id": key_record.fingerprint[-16:],
        "fingerprint": key_record.fingerprint,
        "user_id": user_id_str,
        "email": email,
        "creation_date": key_record.created,
        "expiration_date": key_record.expires,
        "data": pprint.pformat(key),
        "committee_statuses": committee_statuses,
        "status": "success",
    }


async def latest_revision(release: models.Release) -> models.Revision | None:
    if release.latest_revision_number is None:
        return None
    async with db.session() as data:
        return await data.revision(release_name=release.name, number=release.latest_revision_number).get()


async def path_info(release: models.Release, paths: list[pathlib.Path]) -> PathInfo | None:
    info = PathInfo()
    latest_revision_number = release.latest_revision_number
    if latest_revision_number is None:
        return None
    async with db.session() as data:
        await _successes_errors_warnings(data, release, latest_revision_number, info)
        for path in paths:
            # Get artifacts and metadata
            search = re.search(analysis.extension_pattern(), str(path))
            if search:
                if search.group("artifact"):
                    info.artifacts.add(path)
                elif search.group("metadata"):
                    info.metadata.add(path)
    return info


async def release_delete(
    release_name: str, phase: db.Opt[models.ReleasePhase] = db.NOT_SET, include_downloads: bool = True
) -> None:
    """Handle the deletion of database records and filesystem data for a release."""
    async with db.session() as data:
        release = await data.release(name=release_name, phase=phase, _project=True).demand(
            base.ASFQuartException(f"Release '{release_name}' not found.", 404)
        )
        release_dir = util.release_directory_base(release)

        # Delete from the database
        _LOGGER.info("Deleting database records for release: %s", release_name)
        # Cascade should handle this, but we delete manually anyway
        tasks_to_delete = await data.task(project_name=release.project.name, version_name=release.version).all()
        for task in tasks_to_delete:
            await data.delete(task)
        _LOGGER.debug("Deleted %d tasks for %s", len(tasks_to_delete), release_name)

        checks_to_delete = await data.check_result(release_name=release_name).all()
        for check in checks_to_delete:
            await data.delete(check)
        _LOGGER.debug("Deleted %d check results for %s", len(checks_to_delete), release_name)

        await data.delete(release)
        _LOGGER.info("Deleted release record: %s", release_name)
        await data.commit()

    if include_downloads:
        await _delete_release_data_downloads(release)
    await _delete_release_data_filesystem(release_dir, release_name)


async def tasks_ongoing(project_name: str, version_name: str, revision_number: str) -> int:
    async with db.session() as data:
        query = (
            sqlmodel.select(sqlalchemy.func.count())
            .select_from(models.Task)
            .where(
                models.Task.project_name == project_name,
                models.Task.version_name == version_name,
                models.Task.revision_number == revision_number,
                models.validate_instrumented_attribute(models.Task.status).in_(
                    [models.TaskStatus.QUEUED, models.TaskStatus.ACTIVE]
                ),
            )
        )
        result = await data.execute(query)
        return result.scalar_one()


async def unfinished_releases(asfuid: str) -> dict[str, list[models.Release]]:
    releases: dict[str, list[models.Release]] = {}
    async with db.session() as data:
        user_projects = await user.projects(asfuid)
        user_projects.sort(key=lambda p: p.display_name)

        active_phases = [
            models.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
            models.ReleasePhase.RELEASE_CANDIDATE,
            models.ReleasePhase.RELEASE_PREVIEW,
        ]
        for project in user_projects:
            stmt = (
                sqlmodel.select(models.Release)
                .where(
                    models.Release.project_name == project.name,
                    models.validate_instrumented_attribute(models.Release.phase).in_(active_phases),
                )
                .options(db.select_in_load(models.Release.project))
                .order_by(models.validate_instrumented_attribute(models.Release.created).desc())
            )
            result = await data.execute(stmt)
            active_releases = list(result.scalars().all())
            if active_releases:
                active_releases.sort(key=lambda r: r.created, reverse=True)
                releases[project.short_display_name] = active_releases

    return releases


async def upload_keys(
    user_committees: list[str],
    keys_text: str,
    selected_committees: list[str],
    ldap_data: dict[str, str] | None = None,
) -> tuple[list[dict], int, int, list[str]]:
    key_blocks = util.parse_key_blocks(keys_text)
    if not key_blocks:
        raise InteractionError("No valid OpenPGP keys found in the uploaded file")

    # Ensure that the selected committees are ones of which the user is actually a member
    invalid_committees = [committee for committee in selected_committees if (committee not in user_committees)]
    if invalid_committees:
        raise InteractionError(f"Invalid committee selection: {', '.join(invalid_committees)}")

    # TODO: Do we modify this? Store a copy just in case, for the template to use
    submitted_committees = selected_committees[:]

    # Process each key block
    results = await _upload_process_key_blocks(key_blocks, selected_committees, ldap_data=ldap_data)
    # if not results:
    #     raise InteractionError("No keys were added")

    success_count = sum(1 for result in results if result["status"] == "success")
    error_count = len(results) - success_count

    return results, success_count, error_count, submitted_committees


async def upload_keys_bytes(
    user_committees: list[str],
    keys_bytes: bytes,
    selected_committees: list[str],
    ldap_data: dict[str, str] | None = None,
    update_existing: bool = False,
) -> tuple[list[dict], int, int, list[str]]:
    key_blocks = util.parse_key_blocks_bytes(keys_bytes)
    if not key_blocks:
        raise InteractionError("No valid OpenPGP keys found in the uploaded file")

    # Ensure that the selected committees are ones of which the user is actually a member
    invalid_committees = [committee for committee in selected_committees if (committee not in user_committees)]
    if invalid_committees:
        raise InteractionError(f"Invalid committee selection: {', '.join(invalid_committees)}")

    # TODO: Do we modify this? Store a copy just in case, for the template to use
    submitted_committees = selected_committees[:]

    # Process each key block
    results = await _upload_process_key_blocks(
        key_blocks, selected_committees, ldap_data=ldap_data, update_existing=update_existing
    )
    # if not results:
    #     raise InteractionError("No keys were added")

    success_count = sum(1 for result in results if result["status"] == "success")
    error_count = len(results) - success_count

    return results, success_count, error_count, submitted_committees


async def _delete_release_data_downloads(release: models.Release) -> None:
    # Delete hard links from the downloads directory
    finished_dir = util.release_directory(release)
    if await aiofiles.os.path.isdir(finished_dir):
        release_inodes = set()
        async for file_path in util.paths_recursive(finished_dir):
            try:
                stat_result = await aiofiles.os.stat(finished_dir / file_path)
                release_inodes.add(stat_result.st_ino)
            except FileNotFoundError:
                continue

        if release_inodes:
            downloads_dir = util.get_downloads_dir()
            async for link_path in util.paths_recursive(downloads_dir):
                full_link_path = downloads_dir / link_path
                try:
                    link_stat = await aiofiles.os.stat(full_link_path)
                    if link_stat.st_ino in release_inodes:
                        await aiofiles.os.remove(full_link_path)
                        _LOGGER.info(f"Deleted hard link: {full_link_path}")
                except FileNotFoundError:
                    continue


async def _delete_release_data_filesystem(release_dir: pathlib.Path, release_name: str) -> None:
    # Delete from the filesystem
    try:
        if await aiofiles.os.path.isdir(release_dir):
            _LOGGER.info("Deleting filesystem directory: %s", release_dir)
            # Believe this to be another bug in mypy Protocol handling
            # TODO: Confirm that this is a bug, and report upstream
            await aioshutil.rmtree(release_dir)  # type: ignore[call-arg]
            _LOGGER.info("Successfully deleted directory: %s", release_dir)
        else:
            _LOGGER.warning("Filesystem directory not found, skipping deletion: %s", release_dir)
    except Exception as e:
        _LOGGER.exception("Error deleting filesystem directory %s:", release_dir)
        await quart.flash(
            f"Database records for '{release_name}' deleted, but failed to delete filesystem directory: {e!s}",
            "warning",
        )


def _key_latest_self_signature(key: dict) -> datetime.datetime | None:
    fingerprint = key["fingerprint"]
    # TODO: Only 64 bits, which is not at all secure
    fingerprint_suffix = fingerprint[-16:]
    sig_lists = [key.get("sigs", [])] + [sub.get("sigs", []) for sub in key.get("subkey_info", {}).values()]
    latest_sig_date = None
    for sig_list in sig_lists:
        for sig in sig_list:
            if sig[0] in {fingerprint_suffix, fingerprint}:
                if latest_sig_date is None:
                    latest_sig_date = sig[3]
                else:
                    latest_sig_date = max(latest_sig_date, sig[3])
    return datetime.datetime.fromtimestamp(latest_sig_date, tz=datetime.UTC) if latest_sig_date else None


async def _key_user_add_validate_key_properties(public_key: str) -> list[dict]:
    """Validate OpenPGP key string, import it, and return its properties and fingerprint."""
    # import atr.gpgpatch as gpgpatch
    # gnupg = gpgpatch.patch_gnupg()
    import gnupg

    def _sig_with_timestamp(self, args):
        self.curkey["sigs"].append((args[4], args[9], args[10], int(args[5])))

    gnupg.ListKeys.sig = _sig_with_timestamp

    async with ephemeral_gpg_home() as gpg_home:
        gpg = gnupg.GPG(gnupghome=gpg_home)
        import_result = await asyncio.to_thread(gpg.import_keys, public_key)

        if not import_result.fingerprints:
            raise PublicKeyError("Invalid public key format or failed import")

        # List keys to get details
        keys = await asyncio.to_thread(gpg.list_keys, keys=import_result.fingerprints, sigs=True)
        for key in keys:
            if key.get("fingerprint") is None:
                continue
    if not keys:
        _LOGGER.warning(f"No keys found in {public_key}")
        return []

    # Find the specific key details from the list using the fingerprint
    results = []
    for key in keys:
        if key.get("fingerprint") is None:
            _LOGGER.warning(f"Key {key} has no fingerprint")
            continue

        # Validate key algorithm and length
        # https://infra.apache.org/release-signing.html#note
        # Says that keys must be at least 2048 bits
        if (key.get("algo") == "1") and (int(key.get("length", "0")) < 2048):
            raise PublicKeyError("RSA Key is not long enough; must be at least 2048 bits")
        results.append(key)

    return results


async def _successes_errors_warnings(
    data: db.Session, release: models.Release, latest_revision_number: str, info: PathInfo
) -> None:
    # Get successes, warnings, and errors
    successes = await data.check_result(
        release_name=release.name,
        revision_number=latest_revision_number,
        member_rel_path=None,
        status=models.CheckResultStatus.SUCCESS,
    ).all()
    for success in successes:
        if primary_rel_path := success.primary_rel_path:
            info.successes.setdefault(pathlib.Path(primary_rel_path), []).append(success)

    warnings = await data.check_result(
        release_name=release.name,
        revision_number=latest_revision_number,
        member_rel_path=None,
        status=models.CheckResultStatus.WARNING,
    ).all()
    for warning in warnings:
        if primary_rel_path := warning.primary_rel_path:
            info.warnings.setdefault(pathlib.Path(primary_rel_path), []).append(warning)

    errors = await data.check_result(
        release_name=release.name,
        revision_number=latest_revision_number,
        member_rel_path=None,
        status=models.CheckResultStatus.FAILURE,
    ).all()
    for error in errors:
        if primary_rel_path := error.primary_rel_path:
            info.errors.setdefault(pathlib.Path(primary_rel_path), []).append(error)


async def _upload_process_key_blocks(
    key_blocks: list[str],
    selected_committees: list[str],
    ldap_data: dict[str, str] | None = None,
    update_existing: bool = False,
) -> list[dict]:
    """Process OpenPGP key blocks and add them to the user's account."""
    results: list[dict] = []

    # Process each key block
    for i, key_block in enumerate(key_blocks):
        try:
            added_keys = await key_user_add(
                None, key_block, selected_committees, ldap_data=ldap_data, update_existing=update_existing
            )
            for key_info in added_keys:
                key_info["status"] = key_info.get("status", "success")
                key_info["email"] = key_info.get("email", "Unknown")
                key_info["committee_statuses"] = key_info.get("committee_statuses", {})
                results.append(key_info)
            if not added_keys:
                results.append(
                    {
                        "status": "error",
                        "message": "Failed to process key (key_user_add returned None)",
                        "key_id": f"Key #{i + 1}",
                        "fingerprint": "Unknown",
                        "user_id": "Unknown",
                        "email": "Unknown",
                        "committee_statuses": {},
                    }
                )
        except (InteractionError, PublicKeyError) as e:
            # logging.warning(f"InteractionError processing key #{i + 1}: {e}")
            results.append(
                {
                    "status": "error",
                    "message": f"Validation Error: {e}",
                    "key_id": f"Key #{i + 1}",
                    "fingerprint": "Invalid",
                    "user_id": "Unknown",
                    "email": "Unknown",
                    "committee_statuses": {},
                }
            )
        except Exception as e:
            logging.exception(f"Exception processing key #{i + 1}:")
            fingerprint, user_id = "Unknown", "None"
            if isinstance(e, ApacheUserMissingError):
                fingerprint = e.fingerprint or "Unknown"
                user_id = e.primary_uid or "None"
            results.append(
                {
                    "status": "error",
                    "message": f"Internal Exception: {e}",
                    "key_id": f"Key #{i + 1}",
                    "fingerprint": fingerprint,
                    "user_id": user_id,
                    "email": user_id,
                    "committee_statuses": {},
                }
            )

    # Primary key is email, secondary key is fingerprint
    results_sorted = sorted(results, key=lambda x: (x.get("email", "").lower(), x.get("fingerprint", "")))

    return results_sorted
