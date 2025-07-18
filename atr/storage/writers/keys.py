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
import enum
import logging
import tempfile
import time
from typing import TYPE_CHECKING, Any, Final, NoReturn

import pgpy
import pgpy.constants as constants
import sqlalchemy.dialects.sqlite as sqlite

import atr.db as db
import atr.models.schema as schema
import atr.models.sql as sql
import atr.storage as storage
import atr.user as user
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    KeyOutcomes = storage.Outcomes[sql.PublicSigningKey]

PERFORMANCES: Final[dict[int, tuple[str, int]]] = {}
_MEASURE_PERFORMANCE: Final[bool] = False


class KeyStatus(enum.Flag):
    PARSED = 0
    INSERTED = enum.auto()
    LINKED = enum.auto()
    INSERTED_AND_LINKED = INSERTED | LINKED


class Key(schema.Strict):
    status: KeyStatus
    key_model: sql.PublicSigningKey


class PublicKeyError(Exception):
    def __init__(self, key: Key, original_error: Exception):
        self.__key = key
        self.__original_error = original_error

    def __str__(self) -> str:
        return f"PublicKeyError: {self.__original_error}"

    @property
    def key(self) -> Key:
        return self.__key

    @property
    def original_error(self) -> Exception:
        return self.__original_error


def performance(func: Callable[..., Any]) -> Callable[..., Any]:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not _MEASURE_PERFORMANCE:
            return func(*args, **kwargs)

        start = time.perf_counter_ns()
        result = func(*args, **kwargs)
        end = time.perf_counter_ns()
        PERFORMANCES[time.time_ns()] = (func.__name__, end - start)
        return result

    return wrapper


def performance_async(func: Callable[..., Coroutine[Any, Any, Any]]) -> Callable[..., Coroutine[Any, Any, Any]]:
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not _MEASURE_PERFORMANCE:
            return await func(*args, **kwargs)
        start = time.perf_counter_ns()
        result = await func(*args, **kwargs)
        end = time.perf_counter_ns()
        PERFORMANCES[time.time_ns()] = (func.__name__, end - start)
        return result

    return wrapper


class CommitteeMember:
    Key = Key
    KeyStatus = KeyStatus
    PublicKeyError = PublicKeyError

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

    @performance_async
    async def committee(self) -> sql.Committee:
        return await self.__data.committee(name=self.__committee_name, _public_signing_keys=True).demand(
            storage.AccessError(f"Committee not found: {self.__committee_name}")
        )

    @performance_async
    async def upload(self, keys_file_text: str) -> storage.Outcomes[CommitteeMember.Key]:
        outcomes = storage.Outcomes[CommitteeMember.Key]()
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
        outcomes = await self.__database_add_models(outcomes)
        if _MEASURE_PERFORMANCE:
            for key, value in PERFORMANCES.items():
                logging.info(f"{key}: {value}")
        return outcomes

    @performance
    def __block_models(self, key_block: str, ldap_data: dict[str, str]) -> list[CommitteeMember.Key | Exception]:
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
                    key_model = self.__keyring_fingerprint_model(keyring, fingerprint, ldap_data)
                    if key_model is None:
                        # Was not a primary key, so skip it
                        continue
                    key = CommitteeMember.Key(status=CommitteeMember.KeyStatus.PARSED, key_model=key_model)
                    key_list.append(key)
                except Exception as e:
                    key_list.append(e)
            self.__key_block_models_cache[key_block] = key_list
            return key_list

    @performance_async
    async def __database_add_models(
        self, outcomes: storage.Outcomes[CommitteeMember.Key]
    ) -> storage.Outcomes[CommitteeMember.Key]:
        # Try to upsert all models and link to the committee in one transaction
        try:
            outcomes = await self.__database_add_models_core(outcomes)
        except Exception as e:
            # This logging is just so that ruff does not erase e
            logging.info(f"Post-parse error: {e}")

            def raise_post_parse_error(key: CommitteeMember.Key) -> NoReturn:
                nonlocal e
                # We assume here that the transaction was rolled back correctly
                key = CommitteeMember.Key(status=CommitteeMember.KeyStatus.PARSED, key_model=key.key_model)
                raise PublicKeyError(key, e)

            outcomes.update_results(raise_post_parse_error)
        return outcomes

    @performance_async
    async def __database_add_models_core(
        self, outcomes: storage.Outcomes[CommitteeMember.Key]
    ) -> storage.Outcomes[CommitteeMember.Key]:
        via = sql.validate_instrumented_attribute
        key_list = outcomes.results()

        await self.__data.begin_immediate()
        committee = await self.committee()

        key_values = [key.key_model.model_dump(exclude={"committees"}) for key in key_list]
        key_insert_result = await self.__data.execute(
            sqlite.insert(sql.PublicSigningKey)
            .values(key_values)
            .on_conflict_do_nothing(index_elements=["fingerprint"])
            .returning(via(sql.PublicSigningKey.fingerprint))
        )
        key_inserts = {row.fingerprint for row in key_insert_result}
        logging.info(f"Inserted {len(key_inserts)} keys")

        def replace_with_inserted(key: CommitteeMember.Key) -> CommitteeMember.Key:
            if key.key_model.fingerprint in key_inserts:
                key.status = CommitteeMember.KeyStatus.INSERTED
            return key

        outcomes.update_results(replace_with_inserted)

        persisted_fingerprints = {v["fingerprint"] for v in key_values}
        await self.__data.flush()

        existing_fingerprints = {k.fingerprint for k in committee.public_signing_keys}
        new_fingerprints = persisted_fingerprints - existing_fingerprints
        if new_fingerprints:
            link_values = [{"committee_name": self.__committee_name, "key_fingerprint": fp} for fp in new_fingerprints]
            link_insert_result = await self.__data.execute(
                sqlite.insert(sql.KeyLink)
                .values(link_values)
                .on_conflict_do_nothing(index_elements=["committee_name", "key_fingerprint"])
                .returning(via(sql.KeyLink.key_fingerprint))
            )
            link_inserts = {row.key_fingerprint for row in link_insert_result}
            logging.info(f"Inserted {len(link_inserts)} key links")

            def replace_with_linked(key: CommitteeMember.Key) -> CommitteeMember.Key:
                nonlocal link_inserts
                match key:
                    case CommitteeMember.Key(status=CommitteeMember.KeyStatus.INSERTED):
                        if key.key_model.fingerprint in link_inserts:
                            key.status = CommitteeMember.KeyStatus.INSERTED_AND_LINKED
                    case CommitteeMember.Key(status=CommitteeMember.KeyStatus.PARSED):
                        if key.key_model.fingerprint in link_inserts:
                            key.status = CommitteeMember.KeyStatus.LINKED
                return key

            outcomes.update_results(replace_with_linked)
        else:
            logging.info("Inserted 0 key links (none to insert)")

        await self.__data.commit()
        return outcomes

    @performance
    def __keyring_fingerprint_model(
        self, keyring: pgpy.PGPKeyring, fingerprint: str, ldap_data: dict[str, str]
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

    @performance
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
