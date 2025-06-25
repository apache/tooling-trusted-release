#!/usr/bin/env python3

import asyncio
import importlib.util
import sys

if not importlib.util.find_spec("atr"):
    sys.path.append(".")

import atr.db as db
import atr.validate as validate


async def amain() -> None:
    await db.init_database_for_worker()
    async with db.session() as data:
        releases = await data.release().all()
        divergences = 0
        for divergence in validate.releases(releases):
            print(divergence)
            divergences += 1
        print(len(releases), "releases,", divergences, "errors")


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
