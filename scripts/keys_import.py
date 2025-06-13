#!/usr/bin/env python3
# Usage: poetry run python3 scripts/keys_import.py

import asyncio
import sys

import httpx
import pyinstrument

sys.path.append(".")

import atr.db as db
import atr.db.interaction as interaction


async def amain():
    # This runs in serial, and takes several minutes
    # We add about 5 keys per second, and there are around 2500 keys
    # Therefore we expect it to take about 500 seconds, which is just over 8 minutes
    profiler = pyinstrument.Profiler()
    profiler = None
    if profiler is not None:
        profiler.start()
    await db.init_database_for_worker()
    async with db.session() as data:
        committees = await data.committee().all()
        committees = list(committees)
        committees.sort(key=lambda c: c.name.lower())
        limit = 10
        for i, committee in enumerate(committees):
            if (profiler is not None) and (i >= limit):
                break
            async with httpx.AsyncClient() as client:
                response = await client.get(f"https://downloads.apache.org/{committee.name}/KEYS")
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError:
                    print(committee.name + ": no KEYS file")
                    continue
                keys_data = await response.aread()
            keys_text = keys_data.decode("utf-8", errors="replace")
            try:
                _result, yes, no, _committees = await interaction.upload_keys(
                    [committee.name], keys_text, [committee.name]
                )
            except interaction.InteractionError as e:
                print(committee.name + ":", e)
                continue
            print(f"{committee.name}: {yes} successes, {no} failures")
    if profiler is not None:
        profiler.stop()
        print(profiler.output_text(show_all=True, color=True))


def main():
    asyncio.run(amain())


if __name__ == "__main__":
    main()
