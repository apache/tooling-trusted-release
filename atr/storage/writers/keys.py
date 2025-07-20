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
import time
from typing import TYPE_CHECKING, Any, Final, NoReturn

import pgpy
import pgpy.constants as constants
import sqlalchemy.dialects.sqlite as sqlite

import atr.db as db
import atr.models.sql as sql
import atr.storage as storage
import atr.storage.types as types
import atr.user as user
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

PERFORMANCES: Final[dict[int, tuple[str, int]]] = {}
_MEASURE_PERFORMANCE: Final[bool] = False


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


class FoundationMember:
    def __init__(self, credentials: storage.WriteAsFoundationMember, data: db.Session, asf_uid: str):
        if credentials.validate_at_runtime:
            if credentials.authenticated is not True:
                raise storage.AccessError("Writer is not authenticated")
        self.__credentials = credentials
        self.__data = data
        self.__asf_uid = asf_uid
        self.__key_block_models_cache = {}

    @performance_async
    async def ensure_stored_one(self, key_file_text: str) -> types.KeyOutcome:
        return await self.__ensure_one(key_file_text, associate=False)

    @performance
    def __block_model(self, key_block: str, ldap_data: dict[str, str]) -> types.Key | Exception:
        # This cache is only held for the session
        if key_block in self.__key_block_models_cache:
            cached_key_models = self.__key_block_models_cache[key_block]
            if len(cached_key_models) == 1:
                return cached_key_models[0]
            else:
                return ValueError("Expected one key block, got none or multiple")

        with tempfile.NamedTemporaryFile(delete=True) as tmpfile:
            tmpfile.write(key_block.encode())
            tmpfile.flush()
            keyring = pgpy.PGPKeyring()
            fingerprints = keyring.load(tmpfile.name)
            key = None
            for fingerprint in fingerprints:
                try:
                    key_model = self.__keyring_fingerprint_model(keyring, fingerprint, ldap_data)
                    if key_model is None:
                        # Was not a primary key, so skip it
                        continue
                    if key is not None:
                        return ValueError("Expected one key block, got multiple")
                    key = types.Key(status=types.KeyStatus.PARSED, key_model=key_model)
                except Exception as e:
                    return e
        if key is None:
            return ValueError("Expected a key, got none")
        self.__key_block_models_cache[key_block] = [key]
        return key

    @performance_async
    async def __ensure_one(self, key_file_text: str, associate: bool = True) -> types.KeyOutcome:
        try:
            key_blocks = util.parse_key_blocks(key_file_text)
        except Exception as e:
            return storage.OutcomeException(e)
        if len(key_blocks) != 1:
            return storage.OutcomeException(ValueError("Expected one key block, got none or multiple"))
        key_block = key_blocks[0]
        try:
            ldap_data = await util.email_to_uid_map()
            key_model = await asyncio.to_thread(self.__block_model, key_block, ldap_data)
            return storage.OutcomeResult(key_model)
        except Exception as e:
            return storage.OutcomeException(e)

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


class CommitteeParticipant(FoundationMember):
    def __init__(
        self, credentials: storage.WriteAsCommitteeParticipant, data: db.Session, asf_uid: str, committee_name: str
    ):
        super().__init__(credentials, data, asf_uid)
        self.__committee_name = committee_name


class CommitteeMember(CommitteeParticipant):
    def __init__(
        self, credentials: storage.WriteAsCommitteeMember, data: db.Session, asf_uid: str, committee_name: str
    ):
        super().__init__(credentials, data, asf_uid, committee_name)
        self.__committee_name = committee_name

    @performance_async
    async def associate_fingerprint(self, fingerprint: str) -> types.LinkedCommitteeOutcome:
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
                return storage.OutcomeException(storage.AccessError(f"Key not found: {fingerprint}"))
        except Exception as e:
            return storage.OutcomeException(e)
        return storage.OutcomeResult(
            types.LinkedCommittee(
                name=self.__committee_name,
            )
        )

    @performance_async
    async def committee(self) -> sql.Committee:
        return await self.__data.committee(name=self.__committee_name, _public_signing_keys=True).demand(
            storage.AccessError(f"Committee not found: {self.__committee_name}")
        )

    @performance_async
    async def ensure_associated(self, keys_file_text: str) -> storage.Outcomes[types.Key]:
        # TODO: Autogenerate KEYS file
        return await self.__ensure(keys_file_text, associate=True)

    @performance_async
    async def ensure_stored(self, keys_file_text: str) -> storage.Outcomes[types.Key]:
        return await self.__ensure(keys_file_text, associate=False)

    @performance
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
                    key_model = self.__keyring_fingerprint_model(keyring, fingerprint, ldap_data)
                    if key_model is None:
                        # Was not a primary key, so skip it
                        continue
                    key = types.Key(status=types.KeyStatus.PARSED, key_model=key_model)
                    key_list.append(key)
                except Exception as e:
                    key_list.append(e)
        self.__key_block_models_cache[key_block] = key_list
        return key_list

    @performance_async
    async def __database_add_models(
        self, outcomes: storage.Outcomes[types.Key], associate: bool = True
    ) -> storage.Outcomes[types.Key]:
        # Try to upsert all models and link to the committee in one transaction
        try:
            outcomes = await self.__database_add_models_core(outcomes, associate=associate)
        except Exception as e:
            # This logging is just so that ruff does not erase e
            logging.info(f"Post-parse error: {e}")

            def raise_post_parse_error(key: types.Key) -> NoReturn:
                nonlocal e
                # We assume here that the transaction was rolled back correctly
                key = types.Key(status=types.KeyStatus.PARSED, key_model=key.key_model)
                raise types.PublicKeyError(key, e)

            outcomes.update_results(raise_post_parse_error)
        return outcomes

    @performance_async
    async def __database_add_models_core(
        self,
        outcomes: storage.Outcomes[types.Key],
        associate: bool = True,
    ) -> storage.Outcomes[types.Key]:
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

        def replace_with_inserted(key: types.Key) -> types.Key:
            if key.key_model.fingerprint in key_inserts:
                key.status = types.KeyStatus.INSERTED
            return key

        outcomes.update_results(replace_with_inserted)

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
            logging.info(f"Inserted {len(link_inserts)} key links")

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

            outcomes.update_results(replace_with_linked)
        else:
            logging.info("Inserted 0 key links (none to insert)")

        await self.__data.commit()
        return outcomes

    @performance_async
    async def __ensure(self, keys_file_text: str, associate: bool = True) -> storage.Outcomes[types.Key]:
        outcomes = storage.Outcomes[types.Key]()
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
        outcomes = await self.__database_add_models(outcomes, associate=associate)
        if _MEASURE_PERFORMANCE:
            for key, value in PERFORMANCES.items():
                logging.info(f"{key}: {value}")
        return outcomes
