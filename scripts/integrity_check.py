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
        divergences = [d async for d in validate.everything(data)]
        for divergence in divergences:
            print(divergence)
        print(len(divergences), "errors")

    if divergences:
        sys.exit(1)


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
