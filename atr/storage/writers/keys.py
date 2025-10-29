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

# TODO: Add auditing
# TODO: Always raise and catch AccessError

# Removing this will cause circular imports
from __future__ import annotations

import asyncio
import datetime
import tempfile
import textwrap
from typing import NoReturn

import aiofiles
import aiofiles.os
import pgpy
import pgpy.constants as constants
import sqlalchemy.dialects.sqlite as sqlite
import sqlmodel

import atr.config as config
import atr.db as db
import atr.log as log
import atr.models.sql as sql
import atr.storage as storage
import atr.storage.outcome as outcome
import atr.storage.types as types
import atr.user as user
import atr.util as util


class GeneralPublic:
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsGeneralPublic,
        data: db.Session,
    ):
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        self.__asf_uid = write.authorisation.asf_uid


class FoundationCommitter(GeneralPublic):
    def __init__(self, write: storage.Write, write_as: storage.WriteAsFoundationCommitter, data: db.Session):
        super().__init__(write, write_as, data)
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid

        # Specific to this module
        self.__key_block_models_cache = {}

    async def delete_key(self, fingerprint: str) -> outcome.Outcome[sql.PublicSigningKey]:
        try:
            key = await self.__data.public_signing_key(
                fingerprint=fingerprint,
                apache_uid=self.__asf_uid,
                _committees=True,
            ).demand(storage.AccessError(f"Key not found: {fingerprint}"))
            await self.__data.delete(key)
            await self.__data.commit()
            for committee in key.committees:
                wacm = self.__write.as_committee_member_outcome(committee.name).result_or_none()
                if wacm is None:
                    continue
                await wacm.keys.autogenerate_keys_file()
            return outcome.Result(key)
        except Exception as e:
            return outcome.Error(e)

    async def ensure_stored_one(self, key_file_text: str) -> outcome.Outcome[types.Key]:
        return await self.__ensure_one(key_file_text, associate=False)

    def keyring_fingerprint_model(
        self,
        keyring: pgpy.PGPKeyring,
        fingerprint: str,
        ldap_data: dict[str, str],
        original_key_block: str | None = None,
    ) -> sql.PublicSigningKey | None:
        with keyring.key(fingerprint) as key:
            if not key.is_primary:
                return None
            uids = [uid.userid for uid in key.userids]
            asf_uid = self.__uids_asf_uid(uids, ldap_data)

            # TODO: Improve this
            key_size = key.key_size
            length = 0
            if isinstance(key_size, constants.EllipticCurveOID):
                if isinstance(key_size.key_size, int):
                    length = key_size.key_size
                else:
                    raise ValueError(f"Key size is not an integer: {type(key_size.key_size)}, {key_size.key_size}")
            elif isinstance(key_size, int):
                length = key_size
            else:
                raise ValueError(f"Key size is not an integer: {type(key_size)}, {key_size}")

            # Use the original key block if available
            ascii_armored = original_key_block if original_key_block else str(key)

            return sql.PublicSigningKey(
                fingerprint=str(key.fingerprint).lower(),
                algorithm=key.key_algorithm.value,
                length=length,
                created=key.created,
                latest_self_signature=key.expires_at,
                expires=key.expires_at,
                primary_declared_uid=uids[0],
                secondary_declared_uids=uids[1:],
                apache_uid=asf_uid,
                ascii_armored_key=ascii_armored,
            )

    async def keys_file_text(self, committee_name: str) -> str:
        committee = await self.__data.committee(name=committee_name, _public_signing_keys=True).demand(
            storage.AccessError(f"Committee not found: {committee_name}")
        )
        if not committee.public_signing_keys:
            raise storage.AccessError(f"No keys found for committee {committee_name} to generate KEYS file.")

        sorted_keys = sorted(committee.public_signing_keys, key=lambda k: k.fingerprint)

        keys_content_list = []
        for key in sorted_keys:
            apache_uid = key.apache_uid.lower() if key.apache_uid else None
            # TODO: What if there is no email?
            email = util.email_from_uid(key.primary_declared_uid or "") or ""
            comments = []
            comments.append(f"Comment: {key.fingerprint.upper()}")
            if (apache_uid is None) or (email == f"{apache_uid}@apache.org"):
                comments.append(f"Comment: {email}")
            else:
                comments.append(f"Comment: {email} ({apache_uid})")
            comment_lines = "\n".join(comments)
            armored_key = key.ascii_armored_key
            # Use the Sequoia format
            # -----BEGIN PGP PUBLIC KEY BLOCK-----
            # Comment: C46D 6658 489D DE09 CE93  8AF8 7B6A 6401 BF99 B4A3
            # Comment: Redacted Name (CODE SIGNING KEY) <redacted@apache.org>
            #
            # [...]
            if isinstance(armored_key, bytes):
                # TODO: This should not happen, but it does
                armored_key = armored_key.decode("utf-8", errors="replace")
            armored_key = armored_key.replace("BLOCK-----", "BLOCK-----\n" + comment_lines, 1)
            keys_content_list.append(armored_key)

        key_blocks_str = "\n\n\n".join(keys_content_list) + "\n"
        key_count_for_header = len(committee.public_signing_keys)

        return await self.__keys_file_format(
            committee_name=committee_name,
            key_count_for_header=key_count_for_header,
            key_blocks_str=key_blocks_str,
        )

    async def test_user_delete_all(self, test_uid: str) -> outcome.Outcome[int]:
        """Delete all OpenPGP keys and their links for a test user."""
        if not config.get().ALLOW_TESTS:
            return outcome.Error(storage.AccessError("Test key deletion not enabled"))

        try:
            test_user_keys = await self.__data.public_signing_key(apache_uid=test_uid).all()

            deleted_count = 0
            for key in test_user_keys:
                keylinks_query = sqlmodel.select(sql.KeyLink).where(sql.KeyLink.key_fingerprint == key.fingerprint)
                keylinks_result = await self.__data.execute(keylinks_query)
                keylinks = keylinks_result.all()
                for keylink_row in keylinks:
                    await self.__data.delete(keylink_row[0])

                await self.__data.delete(key)
                deleted_count += 1

            await self.__data.commit()
            return outcome.Result(deleted_count)
        except Exception as e:
            return outcome.Error(e)

    def __block_model(self, key_block: str, ldap_data: dict[str, str]) -> types.Key:
        # This cache is only held for the session
        if key_block in self.__key_block_models_cache:
            cached_key_models = self.__key_block_models_cache[key_block]
            if len(cached_key_models) == 1:
                return cached_key_models[0]
            else:
                raise ValueError("Expected one key block, got none or multiple")

        with tempfile.NamedTemporaryFile(delete=True) as tmpfile:
            tmpfile.write(key_block.encode())
            tmpfile.flush()
            keyring = pgpy.PGPKeyring()
            fingerprints = keyring.load(tmpfile.name)
            key = None
            for fingerprint in fingerprints:
                try:
                    key_model = self.keyring_fingerprint_model(
                        keyring, fingerprint, ldap_data, original_key_block=key_block
                    )
                    if key_model is None:
                        # Was not a primary key, so skip it
                        continue
                    if key is not None:
                        raise ValueError("Expected one key block, got multiple")
                    key = types.Key(status=types.KeyStatus.PARSED, key_model=key_model)
                except Exception as e:
                    raise e
        if key is None:
            raise ValueError("Expected a key, got none")
        self.__key_block_models_cache[key_block] = [key]
        return key

    async def __database_add_model(
        self,
        key: types.Key,
    ) -> outcome.Outcome[types.Key]:
        via = sql.validate_instrumented_attribute

        await self.__data.begin_immediate()

        key_values = [key.key_model.model_dump(exclude={"committees"})]
        key_insert_result = await self.__data.execute(
            sqlite.insert(sql.PublicSigningKey)
            .values(key_values)
            .on_conflict_do_nothing(index_elements=["fingerprint"])
            .returning(via(sql.PublicSigningKey.fingerprint))
        )
        await self.__data.commit()

        if key_insert_result.one_or_none() is None:
            log.info(f"Key {key.key_model.fingerprint} already exists in database")
            return outcome.Result(types.Key(status=types.KeyStatus.PARSED, key_model=key.key_model))

        log.info(f"Inserted key {key.key_model.fingerprint}")

        # TODO: PARSED now acts as "ALREADY_ADDED"
        return outcome.Result(types.Key(status=types.KeyStatus.INSERTED, key_model=key.key_model))

    async def __ensure_one(self, key_file_text: str, associate: bool = True) -> outcome.Outcome[types.Key]:
        try:
            key_blocks = util.parse_key_blocks(key_file_text)
        except Exception as e:
            return outcome.Error(e)
        if len(key_blocks) != 1:
            return outcome.Error(ValueError("Expected one key block, got none or multiple"))
        key_block = key_blocks[0]
        try:
            ldap_data = await util.email_to_uid_map()
            key = await asyncio.to_thread(self.__block_model, key_block, ldap_data)
        except Exception as e:
            return outcome.Error(e)
        oc = await self.__database_add_model(key)
        return oc

    async def __keys_file_format(
        self,
        committee_name: str,
        key_count_for_header: int,
        key_blocks_str: str,
    ) -> str:
        timestamp_str = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")
        purpose_text = f"""\
This file contains the {key_count_for_header} OpenPGP public keys used by \
committers of the Apache {committee_name} projects to sign official \
release artifacts. Verifying the signature on a downloaded artifact using one \
of the keys in this file provides confidence that the artifact is authentic \
and was published by the committee.\
"""
        wrapped_purpose = "\n".join(
            textwrap.wrap(
                purpose_text,
                width=62,
                initial_indent="# ",
                subsequent_indent="# ",
                break_long_words=False,
                replace_whitespace=False,
            )
        )

        header_content = f"""\
# Apache Software Foundation (ASF)
# Signing keys for the {committee_name} committee
# Generated at {timestamp_str} UTC
#
{wrapped_purpose}
#
# 1. Import these keys into your GPG keyring:
#    gpg --import KEYS
#
# 2. Verify the signature file against the release artifact:
#    gpg --verify "${{ARTIFACT}}.asc" "${{ARTIFACT}}"
#
# For details on Apache release signing and verification, see:
# https://infra.apache.org/release-signing.html


"""

        full_keys_file_content = header_content + key_blocks_str
        return full_keys_file_content

    def __uids_asf_uid(self, uids: list[str], ldap_data: dict[str, str]) -> str | None:
        # Test data
        test_key_uids = [
            "Apache Tooling (For test use only) <apache-tooling@example.invalid>",
        ]

        if uids == test_key_uids:
            # Allow the test key
            if config.get().ALLOW_TESTS and (self.__asf_uid == "test"):
                # TODO: "test" is already an admin user
                # But we want to narrow that down to only actions like this
                # TODO: Add include_test: bool to user.is_admin?
                return "test"
            if user.is_admin(self.__asf_uid):
                return self.__asf_uid

        # Regular data
        emails = []
        for uid in uids:
            # This returns a lower case email address, whatever the case of the input
            if email := util.email_from_uid(uid):
                if email.endswith("@apache.org"):
                    return email.removesuffix("@apache.org")
                emails.append(email)
        # We did not find a direct @apache.org email address
        # Therefore, search cached LDAP data
        for email in emails:
            if email in ldap_data:
                return ldap_data[email]
        return None


class CommitteeParticipant(FoundationCommitter):
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsCommitteeParticipant,
        data: db.Session,
        committee_name: str,
    ):
        super().__init__(write, write_as, data)
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name

        # Specific to this module
        self.__key_block_models_cache = {}

    async def associate_fingerprint(self, fingerprint: str) -> outcome.Outcome[types.LinkedCommittee]:
        via = sql.validate_instrumented_attribute
        link_values = [{"committee_name": self.__committee_name, "key_fingerprint": fingerprint}]
        try:
            link_insert_result = await self.__data.execute(
                sqlite.insert(sql.KeyLink)
                .values(link_values)
                .on_conflict_do_nothing(index_elements=["committee_name", "key_fingerprint"])
                .returning(via(sql.KeyLink.key_fingerprint))
            )
            if link_insert_result.one_or_none() is None:
                # e = storage.AccessError(f"Key not found: {fingerprint}")
                # return storage.OutcomeException(e)
                pass
            await self.__data.commit()
        except Exception as e:
            return outcome.Error(e)
        try:
            autogenerated_outcome = await self.autogenerate_keys_file()
        except Exception as e:
            return outcome.Error(e)
        return outcome.Result(
            types.LinkedCommittee(
                name=self.__committee_name,
                autogenerated_keys_file=autogenerated_outcome,
            )
        )

    async def autogenerate_keys_file(
        self,
    ) -> outcome.Outcome[str]:
        try:
            base_downloads_dir = util.get_downloads_dir()

            committee = await self.committee()
            is_podling = committee.is_podling

            full_keys_file_content = await self.keys_file_text(self.__committee_name)
            if is_podling:
                committee_keys_dir = base_downloads_dir / "incubator" / self.__committee_name
            else:
                committee_keys_dir = base_downloads_dir / self.__committee_name
            committee_keys_path = committee_keys_dir / "KEYS"
        except Exception as e:
            return outcome.Error(e)

        try:
            await aiofiles.os.makedirs(committee_keys_dir, exist_ok=True)
            await asyncio.to_thread(util.chmod_directories, committee_keys_dir, permissions=0o755)
            await asyncio.to_thread(committee_keys_path.write_text, full_keys_file_content, encoding="utf-8")
        except OSError as e:
            error_msg = f"Failed to write KEYS file for committee {self.__committee_name}: {e}"
            return outcome.Error(storage.AccessError(error_msg))
        except Exception as e:
            error_msg = f"An unexpected error occurred writing KEYS for committee {self.__committee_name}: {e}"
            log.exception(f"An unexpected error occurred writing KEYS for committee {self.__committee_name}: {e}")
            return outcome.Error(storage.AccessError(error_msg))
        return outcome.Result(str(committee_keys_path))

    async def committee(self) -> sql.Committee:
        return await self.__data.committee(name=self.__committee_name, _public_signing_keys=True).demand(
            storage.AccessError(f"Committee not found: {self.__committee_name}")
        )

    @property
    def committee_name(self) -> str:
        return self.__committee_name

    async def ensure_associated(self, keys_file_text: str) -> outcome.List[types.Key]:
        outcomes: outcome.List[types.Key] = await self.__ensure(keys_file_text, associate=True)
        if outcomes.any_result:
            await self.autogenerate_keys_file()
        return outcomes

    async def ensure_stored(self, keys_file_text: str) -> outcome.List[types.Key]:
        outcomes: outcome.List[types.Key] = await self.__ensure(keys_file_text, associate=False)
        if outcomes.any_result:
            await self.autogenerate_keys_file()
        return outcomes

    async def import_keys_file(self, project_name: str, version_name: str) -> outcome.List[types.Key]:
        release = await self.__data.release(
            project_name=project_name,
            version=version_name,
            _committee=True,
        ).demand(storage.AccessError(f"Release not found: {project_name} {version_name}"))
        keys_path = util.release_directory(release) / "KEYS"
        async with aiofiles.open(keys_path, encoding="utf-8") as f:
            keys_file_text = await f.read()
        if release.committee is None:
            raise storage.AccessError("No committee found for release")
        if release.committee.name != self.__committee_name:
            raise storage.AccessError(
                f"Release {project_name} {version_name} is not associated with committee {self.__committee_name}"
            )

        outcomes = await self.ensure_associated(keys_file_text)
        # Remove the KEYS file if 100% imported
        if (outcomes.result_count > 0) and (outcomes.error_count == 0):
            description = "Removed KEYS file after successful import through web interface"
            async with self.__write_as.revision.create_and_manage(
                project_name, version_name, self.__asf_uid, description=description
            ) as creating:
                path_in_new_revision = creating.interim_path / "KEYS"
                await aiofiles.os.remove(path_in_new_revision)
        return outcomes

    def __block_models(self, key_block: str, ldap_data: dict[str, str]) -> list[types.Key | Exception]:
        # This cache is only held for the session
        if key_block in self.__key_block_models_cache:
            return self.__key_block_models_cache[key_block]

        with tempfile.NamedTemporaryFile(delete=True) as tmpfile:
            tmpfile.write(key_block.encode())
            tmpfile.flush()
            keyring = pgpy.PGPKeyring()
            fingerprints = keyring.load(tmpfile.name)
            key_list = []
            for fingerprint in fingerprints:
                try:
                    key_model = self.keyring_fingerprint_model(
                        keyring, fingerprint, ldap_data, original_key_block=key_block
                    )
                    if key_model is None:
                        # Was not a primary key, so skip it
                        continue
                    key = types.Key(status=types.KeyStatus.PARSED, key_model=key_model)
                    key_list.append(key)
                except Exception as e:
                    key_list.append(e)
        self.__key_block_models_cache[key_block] = key_list
        return key_list

    async def __database_add_models(
        self, outcomes: outcome.List[types.Key], associate: bool = True
    ) -> outcome.List[types.Key]:
        # Try to upsert all models and link to the committee in one transaction
        try:
            outcomes = await self.__database_add_models_core(outcomes, associate=associate)
        except Exception as e:
            # This logging is just so that ruff does not erase e
            log.info(f"Post-parse error: {e}")

            def raise_post_parse_error(key: types.Key) -> NoReturn:
                nonlocal e
                # We assume here that the transaction was rolled back correctly
                key = types.Key(status=types.KeyStatus.PARSED, key_model=key.key_model)
                raise types.PublicKeyError(key, e)

            outcomes.update_roes(Exception, raise_post_parse_error)
        return outcomes

    async def __database_add_models_core(
        self,
        outcomes: outcome.List[types.Key],
        associate: bool = True,
    ) -> outcome.List[types.Key]:
        via = sql.validate_instrumented_attribute
        key_list = outcomes.results()

        await self.__data.begin_immediate()
        committee = await self.committee()

        key_values = [key.key_model.model_dump(exclude={"committees"}) for key in key_list]
        if key_values:
            stmt = sqlite.insert(sql.PublicSigningKey).values(key_values)
            stmt = stmt.on_conflict_do_update(
                index_elements=["fingerprint"],
                set_={"apache_uid": stmt.excluded.apache_uid},
            )
            key_insert_result = await self.__data.execute(
                stmt.returning(via(sql.PublicSigningKey.fingerprint)),
            )
            key_inserts = {row.fingerprint for row in key_insert_result}
            log.info(f"Inserted or updated {len(key_inserts)} keys")
        else:
            # TODO: Warn the user about any keys that were already inserted
            key_inserts = set()
            log.info("Inserted 0 keys (no keys to insert)")

        def replace_with_inserted(key: types.Key) -> types.Key:
            if key.key_model.fingerprint in key_inserts:
                key.status = types.KeyStatus.INSERTED
            return key

        outcomes.update_roes(Exception, replace_with_inserted)

        persisted_fingerprints = {v["fingerprint"] for v in key_values}
        await self.__data.flush()

        existing_fingerprints = {k.fingerprint for k in committee.public_signing_keys}
        new_fingerprints = persisted_fingerprints - existing_fingerprints
        if new_fingerprints and associate:
            link_values = [{"committee_name": self.__committee_name, "key_fingerprint": fp} for fp in new_fingerprints]
            link_insert_result = await self.__data.execute(
                sqlite.insert(sql.KeyLink)
                .values(link_values)
                .on_conflict_do_nothing(index_elements=["committee_name", "key_fingerprint"])
                .returning(via(sql.KeyLink.key_fingerprint))
            )
            link_inserts = {row.key_fingerprint for row in link_insert_result}
            log.info(f"Inserted {len(link_inserts)} key links")

            def replace_with_linked(key: types.Key) -> types.Key:
                nonlocal link_inserts
                match key:
                    case types.Key(status=types.KeyStatus.INSERTED):
                        if key.key_model.fingerprint in link_inserts:
                            key.status = types.KeyStatus.INSERTED_AND_LINKED
                    case types.Key(status=types.KeyStatus.PARSED):
                        if key.key_model.fingerprint in link_inserts:
                            key.status = types.KeyStatus.LINKED
                return key

            outcomes.update_roes(Exception, replace_with_linked)
        else:
            log.info("Inserted 0 key links (none to insert)")

        await self.__data.commit()
        return outcomes

    async def __ensure(self, keys_file_text: str, associate: bool = True) -> outcome.List[types.Key]:
        outcomes = outcome.List[types.Key]()
        try:
            ldap_data = await util.email_to_uid_map()
            key_blocks = util.parse_key_blocks(keys_file_text)
        except Exception as e:
            outcomes.append_error(e)
            return outcomes
        for key_block in key_blocks:
            try:
                # TODO: Change self.__block_models to return outcomes
                key_models = await asyncio.to_thread(self.__block_models, key_block, ldap_data)
                outcomes.extend_roes(Exception, key_models)
            except Exception as e:
                outcomes.append_error(e)
        # Try adding the keys to the database
        # If not, all keys will be replaced with a PostParseError
        return await self.__database_add_models(outcomes, associate=associate)


class CommitteeMember(CommitteeParticipant):
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsCommitteeMember,
        data: db.Session,
        committee_name: str,
    ):
        super().__init__(write, write_as, data, committee_name)
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name


class FoundationAdmin(CommitteeMember):
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsFoundationAdmin,
        data: db.Session,
        committee_name: str,
    ):
        super().__init__(write, write_as, data, committee_name)
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name

    @property
    def committee_name(self) -> str:
        return self.__committee_name
