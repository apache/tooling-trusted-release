#!/usr/bin/env python3
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

# Usage: poetry run python3 scripts/keys_import.py

import asyncio
import contextlib
import os
import sys
import time
import traceback

sys.path.append(".")


import atr.config as config
import atr.db as db
import atr.storage as storage
import atr.storage.types as types
import atr.util as util

TARGET_FINGERPRINT = "63db20dd87e4b34fcd9bbb0da9a14f22f57da182"


def get(entry: dict, prop: str) -> str | None:
    if prop in entry:
        values = entry[prop]
        if values:
            return values[0]
    return None


def print_and_flush(message: str) -> None:
    print(message)
    sys.stdout.flush()


def log_target_key_debug(outcomes, committee_name: str, email_to_uid: dict[str, str]) -> None:  # noqa: C901
    target = TARGET_FINGERPRINT.lower()
    for result in outcomes.results():
        key_model = result.key_model
        if key_model.fingerprint == target:
            status = getattr(result.status, "name", str(result.status))
            print_and_flush(
                f"DEBUG fingerprint={target} committee={committee_name} status={status} "
                f"apache_uid={key_model.apache_uid} primary_uid={key_model.primary_declared_uid} "
                f"secondary_uids={key_model.secondary_declared_uids}"
            )
            uids: list[str] = []
            if key_model.primary_declared_uid:
                uids.append(key_model.primary_declared_uid)
            if key_model.secondary_declared_uids:
                uids.extend(key_model.secondary_declared_uids)
            for uid_value in uids:
                email = util.email_from_uid(uid_value)
                ldap_uid = email_to_uid.get(email) if email else None
                mapped = None
                if email and email.endswith("@apache.org"):
                    mapped = email.removesuffix("@apache.org")
                elif ldap_uid:
                    mapped = ldap_uid
                print_and_flush(
                    f"DEBUG uid={uid_value} extracted_email={email} ldap_uid={ldap_uid} mapped_uid={mapped}"
                )
    for error in outcomes.errors():
        fingerprint = None
        apache_uid = None
        primary_uid = None
        secondary_uids = None
        detail = str(error)
        if isinstance(error, types.PublicKeyError):
            key_model = error.key.key_model
            fingerprint = key_model.fingerprint
            apache_uid = key_model.apache_uid
            primary_uid = key_model.primary_declared_uid
            secondary_uids = key_model.secondary_declared_uids
            detail = str(error.original_error)
        if fingerprint == target:
            print_and_flush(
                f"DEBUG fingerprint={target} committee={committee_name} error={type(error).__name__} "
                f"apache_uid={apache_uid} primary_uid={primary_uid} secondary_uids={secondary_uids} detail={detail}"
            )


@contextlib.contextmanager
def log_to_file(conf: config.AppConfig):
    log_file_path = os.path.join(conf.STATE_DIR, "keys_import.log")
    # This should not be required
    os.makedirs(conf.STATE_DIR, exist_ok=True)

    original_stdout = sys.stdout
    original_stderr = sys.stderr
    with open(log_file_path, "a") as f:
        sys.stdout = f
        sys.stderr = f
        try:
            yield
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr


async def keys_import(conf: config.AppConfig, asf_uid: str) -> None:
    # Runs as a standalone script, so we need a worker style database connection
    await db.init_database_for_worker()
    # Print the time and current PID
    print(f"--- {time.strftime('%Y-%m-%d %H:%M:%S')} by pid {os.getpid()} ---")
    sys.stdout.flush()

    # Get all email addresses in LDAP
    # We'll discard them when we're finished
    start = time.perf_counter_ns()
    email_to_uid = await util.email_to_uid_map()
    end = time.perf_counter_ns()
    print_and_flush(f"LDAP search took {(end - start) / 1000000} ms")
    print_and_flush(f"Email addresses from LDAP: {len(email_to_uid)}")

    # Get the KEYS file of each committee
    async with db.session() as data:
        committees = await data.committee().all()
    committees = list(committees)
    committees.sort(key=lambda c: c.name.lower())

    urls = []
    for committee in committees:
        if committee.is_podling:
            url = f"https://downloads.apache.org/incubator/{committee.name}/KEYS"
        else:
            url = f"https://downloads.apache.org/{committee.name}/KEYS"
        urls.append(url)

    total_yes = 0
    total_no = 0
    async for url, status, content in util.get_urls_as_completed(urls):
        # For each remote KEYS file, check that it responded 200 OK
        # Extract committee name from URL
        # This works for both /committee/KEYS and /incubator/committee/KEYS
        committee_name = url.rsplit("/", 2)[-2]
        if status != 200:
            print_and_flush(f"{committee_name} error: {status}")
            continue

        # Parse the KEYS file and add it to the database
        # We use a separate storage.write() context for each committee to avoid transaction conflicts
        async with storage.write(asf_uid) as write:
            wafa = write.as_foundation_admin(committee_name)
            keys_file_text = content.decode("utf-8", errors="replace")
            outcomes = await wafa.keys.ensure_associated(keys_file_text)
            log_target_key_debug(outcomes, committee_name, email_to_uid)
            yes = outcomes.result_count
            no = outcomes.error_count
            if no:
                outcomes.errors_print()

            # Print and record the number of keys that were okay and failed
            print_and_flush(f"{committee_name} {yes} {no}")
            total_yes += yes
            total_no += no
    print_and_flush(f"Total okay: {total_yes}")
    print_and_flush(f"Total failed: {total_no}")
    end = time.perf_counter_ns()
    print_and_flush(f"Script took {(end - start) / 1000000} ms")
    print_and_flush("")


async def amain() -> None:
    conf = config.AppConfig()
    with log_to_file(conf):
        try:
            await keys_import(conf, sys.argv[1])
        except Exception as e:
            print_and_flush(f"Error: {e}")
            traceback.print_exc()
            sys.stdout.flush()
            sys.exit(1)


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
