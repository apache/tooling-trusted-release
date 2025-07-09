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

sys.path.append(".")


import atr.config as config
import atr.db as db
import atr.db.interaction as interaction
import atr.util as util


def get(entry: dict, prop: str) -> str | None:
    if prop in entry:
        values = entry[prop]
        if values:
            return values[0]
    return None


def write(message: str) -> None:
    print(message)
    sys.stdout.flush()


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


async def keys_import(conf: config.AppConfig) -> None:
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
    write(f"LDAP search took {(end - start) / 1000000} ms")
    write(f"Email addresses from LDAP: {len(email_to_uid)}")

    # Open an ATR database connection
    async with db.session() as data:
        # Get the KEYS file of each committee
        committees = await data.committee().all()
        committees = list(committees)
        committees.sort(key=lambda c: c.name.lower())
        urls = [f"https://downloads.apache.org/{committee.name}/KEYS" for committee in committees]
        total_yes = 0
        total_no = 0
        async for url, status, content in util.get_urls_as_completed(urls):
            # For each remote KEYS file, check that it responded 200 OK
            committee_name = url.rsplit("/", 2)[-2]
            if status != 200:
                write(f"{committee_name} error: {status}")
                continue

            # Parse the KEYS file and add it to the database
            # TODO: We could have this return the keys to make it more efficient
            # Then we could use the bulk upsert query method
            try:
                _result, yes, no, _committees = await interaction.upload_keys_bytes(
                    [committee_name], content, [committee_name], ldap_data=email_to_uid, update_existing=True
                )
            except Exception as e:
                write(f"{committee_name} error: {e}")
                continue

            # Print and record the number of keys that were okay and failed
            write(f"{committee_name} {yes} {no}")
            total_yes += yes
            total_no += no
        write(f"Total okay: {total_yes}")
        write(f"Total failed: {total_no}")
    end = time.perf_counter_ns()
    write(f"Script took {(end - start) / 1000000} ms")
    write("")


async def amain() -> None:
    conf = config.AppConfig()
    with log_to_file(conf):
        await keys_import(conf)


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
