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

import sqlalchemy
import sqlmodel

import atr.analysis as analysis
import atr.db as db
import atr.db.models as models
import atr.ldap as ldap
import atr.schema as schema
import atr.user as user
import atr.util as util

_LOGGER: Final = logging.getLogger(__name__)


class ApacheUserMissingError(RuntimeError):
    def __init__(self, message: str, fingerprint: str | None, primary_uid: str | None) -> None:
        super().__init__(message)
        self.fingerprint = fingerprint
        self.primary_uid = primary_uid


class PathInfo(schema.Strict):
    artifacts: set[pathlib.Path] = schema.factory(set)
    errors: dict[pathlib.Path, list[models.CheckResult]] = schema.factory(dict)
    metadata: set[pathlib.Path] = schema.factory(set)
    successes: dict[pathlib.Path, list[models.CheckResult]] = schema.factory(dict)
    warnings: dict[pathlib.Path, list[models.CheckResult]] = schema.factory(dict)


@contextlib.asynccontextmanager
async def ephemeral_gpg_home() -> AsyncGenerator[str]:
    """Create a temporary directory for an isolated GPG home, and clean it up on exit."""
    async with util.async_temporary_directory(prefix="gpg-") as temp_dir:
        yield str(temp_dir)


async def key_user_add(asf_uid: str | None, public_key: str, selected_committees: list[str]) -> dict | None:
    if not public_key:
        raise RuntimeError("Public key is required")

    # Validate the key using GPG and get its properties
    key, _fingerprint = await _key_user_add_validate_key_properties(public_key)

    # Determine ASF UID if not provided
    if asf_uid is None:
        for uid_str in key["uids"]:
            if match := re.search(r"([A-Za-z0-9]+)@apache.org", uid_str):
                asf_uid = match.group(1).lower()
                break
        else:
            _LOGGER.warning(f"key_user_add called with no ASF UID found in key UIDs: {key.get('uids')}")
            for uid_str in key.get("uids", []):
                if asf_uid := await asyncio.to_thread(_asf_uid_from_uid_str, uid_str):
                    break
    if asf_uid is None:
        # We place this here to make it easier on the type checkers
        non_asf_uids = key.get("uids", [])
        first_non_asf_uid = non_asf_uids[0] if non_asf_uids else "None"
        raise ApacheUserMissingError(
            f"No Apache UID found. Fingerprint: {key.get('fingerprint', 'Unknown')}. Primary UID: {first_non_asf_uid}",
            fingerprint=key.get("fingerprint"),
            primary_uid=first_non_asf_uid,
        )

    # Store key in database
    async with db.session() as data:
        return await key_user_session_add(asf_uid, public_key, key, selected_committees, data)


async def key_user_session_add(
    asf_uid: str,
    public_key: str,
    key: dict,
    selected_committees: list[str],
    data: db.Session,
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

    async with data.begin():
        existing = await data.public_signing_key(fingerprint=fingerprint, apache_uid=asf_uid).get()

        if existing:
            logging.info(f"Found existing key {fingerprint}, updating associations")
            key_record = existing
        else:
            # Key doesn't exist, create it
            logging.info(f"Adding new key {fingerprint}")
            created = datetime.datetime.fromtimestamp(int(key["date"]), tz=datetime.UTC)
            expires = (
                datetime.datetime.fromtimestamp(int(key["expires"]), tz=datetime.UTC) if key.get("expires") else None
            )

            key_record = models.PublicSigningKey(
                fingerprint=fingerprint,
                algorithm=int(key["algo"]),
                length=int(key.get("length", "0")),
                created=created,
                expires=expires,
                primary_declared_uid=uids[0] if uids else None,
                secondary_declared_uids=uids[1:],
                apache_uid=asf_uid,
                ascii_armored_key=public_key,
            )
            data.add(key_record)
            await data.flush()
            await data.refresh(key_record)

        # Safety check, in case of strange flushes
        if not key_record:
            raise RuntimeError(f"Failed to obtain valid key record for fingerprint {fingerprint}")

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
                    logging.debug(f"Linking key {fingerprint} to committee {committee_name}")
                    link = models.KeyLink(committee_name=committee.name, key_fingerprint=key_record.fingerprint)
                    data.add(link)
                else:
                    committee_statuses[committee_name] = "already_linked"
                    logging.debug(f"Link already exists for key {fingerprint} and committee {committee_name}")
            else:
                logging.warning(f"Could not find committee {committee_name} to link key {fingerprint}")
                continue

    # Extract email for sorting
    user_id_str = key_record.primary_declared_uid or ""
    email_match = re.search(r"<([^>]+)>", user_id_str)
    email = email_match.group(1) if email_match else user_id_str

    return {
        "key_id": key_record.fingerprint[:16],
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
    for path in paths:
        # Get template and substitutions
        # elements = {
        #     "core": release.project.name,
        #     "version": release.version,
        #     "sub": None,
        #     "template": None,
        #     "substitutions": None,
        # }
        # template, substitutions = analysis.filename_parse(str(path), elements)
        # info.templates[path] = template
        # info.substitutions[path] = analysis.substitutions_format(substitutions) or "none"

        # Get artifacts and metadata
        search = re.search(analysis.extension_pattern(), str(path))
        if search:
            if search.group("artifact"):
                info.artifacts.add(path)
            elif search.group("metadata"):
                info.metadata.add(path)

        # Get successes, warnings, and errors
        async with db.session() as data:
            info.successes[path] = list(
                await data.check_result(
                    release_name=release.name,
                    revision_number=latest_revision_number,
                    primary_rel_path=str(path),
                    member_rel_path=None,
                    status=models.CheckResultStatus.SUCCESS,
                ).all()
            )
            info.warnings[path] = list(
                await data.check_result(
                    release_name=release.name,
                    revision_number=latest_revision_number,
                    primary_rel_path=str(path),
                    member_rel_path=None,
                    status=models.CheckResultStatus.WARNING,
                ).all()
            )
            info.errors[path] = list(
                await data.check_result(
                    release_name=release.name,
                    revision_number=latest_revision_number,
                    primary_rel_path=str(path),
                    member_rel_path=None,
                    status=models.CheckResultStatus.FAILURE,
                ).all()
            )
    return info


async def tasks_ongoing(project_name: str, version_name: str, revision_number: str) -> int:
    release_name = models.release_name(project_name, version_name)
    async with db.session() as data:
        query = (
            sqlmodel.select(sqlalchemy.func.count())
            .select_from(models.Task)
            .where(
                models.Task.release_name == release_name,
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


def _asf_uid_from_uid_str(uid_str: str) -> str | None:
    if not (email_match := re.search(r"<([^>]+)>", uid_str)):
        return None
    email = email_match.group(1)
    if email.endswith("@apache.org"):
        return None
    ldap_params = ldap.SearchParameters(email_query=email)
    ldap.search(ldap_params)
    if not (ldap_params.results_list and ("uid" in ldap_params.results_list[0])):
        return None
    ldap_uid_val = ldap_params.results_list[0]["uid"]
    return ldap_uid_val[0] if isinstance(ldap_uid_val, list) else ldap_uid_val


async def _key_user_add_validate_key_properties(public_key: str) -> tuple[dict, str]:
    """Validate GPG key string, import it, and return its properties and fingerprint."""
    import gnupg

    async with ephemeral_gpg_home() as gpg_home:
        gpg = gnupg.GPG(gnupghome=gpg_home)
        import_result = await asyncio.to_thread(gpg.import_keys, public_key)

        if not import_result.fingerprints:
            raise RuntimeError("Invalid public key format or failed import")

        fingerprint = import_result.fingerprints[0]
        if fingerprint is None:
            # Should be unreachable given the previous check, but satisfy type checker
            raise RuntimeError("Failed to get fingerprint after import")
        fingerprint_lower = fingerprint.lower()

        # List keys to get details
        keys = await asyncio.to_thread(gpg.list_keys)

    # Find the specific key details from the list using the fingerprint
    key_details = None
    for k in keys:
        if k.get("fingerprint") is not None and k["fingerprint"].lower() == fingerprint_lower:
            key_details = k
            break

    if not key_details:
        # This might indicate an issue with gpg.list_keys or the environment
        logging.error(
            f"Could not find key details for fingerprint {fingerprint_lower}"
            f" after successful import. Keys listed: {keys}"
        )
        raise RuntimeError("Failed to retrieve key details after import")

    # Validate key algorithm and length
    # https://infra.apache.org/release-signing.html#note
    # Says that keys must be at least 2048 bits
    if (key_details.get("algo") == "1") and (int(key_details.get("length", "0")) < 2048):
        raise RuntimeError("RSA Key is not long enough; must be at least 2048 bits")

    return key_details, fingerprint_lower
