#!/usr/bin/env python3
# Usage: poetry run python3 scripts/keys_import.py

import asyncio
import sys
import time

sys.path.append(".")


import atr.config as config
import atr.db as db
import atr.db.interaction as interaction
import atr.ldap as ldap
import atr.util as util


def get(entry, prop):
    if prop in entry:
        values = entry[prop]
        if values:
            return values[0]
    return None


async def amain():
    # Runs as a standalone script, so we need a worker style database connection
    await db.init_database_for_worker()

    # Get all email addresses in LDAP
    # We'll discard them when we're finished
    conf = config.AppConfig()
    bind_dn = conf.LDAP_BIND_DN
    bind_password = conf.LDAP_BIND_PASSWORD
    ldap_params = ldap.SearchParameters(
        uid_query="*",
        bind_dn_from_config=bind_dn,
        bind_password_from_config=bind_password,
        email_only=True,
    )
    start = time.perf_counter_ns()
    await asyncio.to_thread(ldap.search, ldap_params)
    end = time.perf_counter_ns()
    print("LDAP search took", (end - start) / 1000000, "ms")

    # Map the LDAP addresses to Apache UIDs
    email_to_uid = {}
    for entry in ldap_params.results_list:
        uid = entry.get("uid", [""])[0]
        if mail := get(entry, "mail"):
            email_to_uid[mail] = uid
        if alt_email := get(entry, "asf-altEmail"):
            email_to_uid[alt_email] = uid
        if committer_email := get(entry, "asf-committer-email"):
            email_to_uid[committer_email] = uid
    print("Email addresses from LDAP:", len(email_to_uid))

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
                print(committee_name, "error:", status)
                continue

            # Parse the KEYS file and add it to the database
            # TODO: We could have this return the keys to make it more efficient
            # Then we could use the bulk upsert query method
            try:
                _result, yes, no, _committees = await interaction.upload_keys_bytes(
                    [committee_name], content, [committee_name], ldap_data=email_to_uid
                )
            except Exception as e:
                print(committee_name, "error:", e)
                continue

            # Print and record the number of keys that were okay and failed
            print(committee_name, yes, no)
            total_yes += yes
            total_no += no
        print("Total okay:", total_yes)
        print("Total failed:", total_no)


def main():
    asyncio.run(amain())


if __name__ == "__main__":
    main()
