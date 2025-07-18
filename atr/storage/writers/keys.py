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

# Removing this will cause circular imports
from __future__ import annotations

import asyncio
import logging
import tempfile
from typing import TYPE_CHECKING, NoReturn

import pgpy
import pgpy.constants as constants
import sqlalchemy.dialects.sqlite as sqlite

import atr.db as db
import atr.models.sql as sql
import atr.storage as storage
import atr.user as user
import atr.util as util

if TYPE_CHECKING:
    KeyOutcomes = storage.Outcomes[sql.PublicSigningKey]


class PostParseError(Exception):
    def __init__(self, key: sql.PublicSigningKey, original_error: Exception):
        self.__key = key
        self.__original_error = original_error

    def __str__(self) -> str:
        return f"PostParseError: {self.__original_error}"

    @property
    def key(self) -> sql.PublicSigningKey:
        return self.__key

    @property
    def original_error(self) -> Exception:
        return self.__original_error


class CommitteeMember:
    def __init__(
        self, credentials: storage.WriteAsCommitteeMember, data: db.Session, asf_uid: str, committee_name: str
    ):
        if credentials.validate_at_runtime:
            if credentials.authenticated is not True:
                raise storage.AccessError("Writer is not authenticated")
        self.__credentials = credentials
        self.__data = data
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name
        self.__key_block_models_cache = {}

    async def committee(self) -> sql.Committee:
        return await self.__data.committee(name=self.__committee_name, _public_signing_keys=True).demand(
            storage.AccessError(f"Committee not found: {self.__committee_name}")
        )

    async def upload(self, keys_file_text: str) -> KeyOutcomes:
        outcomes = storage.Outcomes[sql.PublicSigningKey]()
        try:
            ldap_data = await util.email_to_uid_map()
            key_blocks = util.parse_key_blocks(keys_file_text)
        except Exception as e:
            outcomes.append(e)
            return outcomes
        for key_block in key_blocks:
            try:
                key_models = await asyncio.to_thread(self.__block_models, key_block, ldap_data)
                outcomes.extend(key_models)
            except Exception as e:
                outcomes.append(e)
        # Try adding the keys to the database
        # If not, all keys will be replaced with a PostParseError
        return await self.__database_add_models(outcomes)

    def __block_models(self, key_block: str, ldap_data: dict[str, str]) -> list[sql.PublicSigningKey | Exception]:
        # This cache is only held for the session
        if key_block in self.__key_block_models_cache:
            return self.__key_block_models_cache[key_block]

        with tempfile.NamedTemporaryFile(delete=True) as tmpfile:
            tmpfile.write(key_block.encode())
            tmpfile.flush()
            keyring = pgpy.PGPKeyring()
            fingerprints = keyring.load(tmpfile.name)
            models = []
            for fingerprint in fingerprints:
                try:
                    model = self.__keyring_fingerprint_model(keyring, fingerprint, ldap_data)
                    if model is None:
                        # Was not a primary key, so skip it
                        continue
                    models.append(model)
                except Exception as e:
                    models.append(e)
            self.__key_block_models_cache[key_block] = models
            return models

    async def __database_add_models(self, outcomes: KeyOutcomes) -> KeyOutcomes:
        # Try to upsert all models and link to the committee in one transaction
        try:
            key_models = outcomes.results()

            await self.__data.begin_immediate()
            committee = await self.committee()

            persisted_fingerprints: set[str] = set()
            for model in key_models:
                merged_key: sql.PublicSigningKey = await self.__data.merge(model)
                persisted_fingerprints.add(merged_key.fingerprint)
            await self.__data.flush()

            existing_fingerprints = {k.fingerprint for k in committee.public_signing_keys}
            new_fingerprints = persisted_fingerprints - existing_fingerprints

            if new_fingerprints:
                insert_values = [
                    {"committee_name": self.__committee_name, "key_fingerprint": fp} for fp in new_fingerprints
                ]
                stmt = sqlite.insert(sql.KeyLink).values(insert_values)
                stmt = stmt.on_conflict_do_nothing(index_elements=["committee_name", "key_fingerprint"])
                await self.__data.execute(stmt)

            await self.__data.commit()
        except Exception as e:
            # This logging is just so that ruff does not erase e
            logging.info(f"Post-parse error: {e}")

            def raise_post_parse_error(model: sql.PublicSigningKey) -> NoReturn:
                nonlocal e
                raise PostParseError(model, e)

            outcomes.update_results(raise_post_parse_error)
        return outcomes

    def __keyring_fingerprint_model(
        self, keyring: pgpy.PGPKeyring, fingerprint: str, ldap_data: dict[str, str]
    ) -> sql.PublicSigningKey | None:
        with keyring.key(fingerprint) as key:
            if not key.is_primary:
                return None
            uids = [uid.userid for uid in key.userids]
            asf_uid = self.__uids_asf_uid(uids, ldap_data)
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
                ascii_armored_key=str(key),
            )

    def __uids_asf_uid(self, uids: list[str], ldap_data: dict[str, str]) -> str | None:
        # Test data
        test_key_uids = [
            "Apache Tooling (For test use only) <apache-tooling@example.invalid>",
        ]
        is_admin = user.is_admin(self.__asf_uid)
        if (uids == test_key_uids) and is_admin:
            # Allow the test key
            # TODO: We should fix the test key, not add an exception for it
            # But the admin check probably makes this safe enough
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
