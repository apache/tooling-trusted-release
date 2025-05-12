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

import logging
from typing import Final

import aiofiles

import atr.db as db
import atr.db.interaction as interaction
import atr.db.models as models
import atr.schema as schema
import atr.tasks.checks as checks
from atr import util

_LOGGER: Final = logging.getLogger(__name__)


class ImportFile(schema.Strict):
    """Import a KEYS file from a draft release candidate revision."""

    release_name: str
    abs_keys_path: str


@checks.with_model(ImportFile)
async def import_file(args: ImportFile) -> str | None:
    """Import a KEYS file from a draft release candidate revision."""
    async with db.session() as data:
        release = await data.release(name=args.release_name).demand(
            RuntimeError(f"Release {args.release_name} not found")
        )
        if release.phase != models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
            raise RuntimeError(f"Release {args.release_name} is not in the DRAFT phase")

    async with aiofiles.open(args.abs_keys_path, "rb") as keys_file:
        keys_text = await keys_file.read()
    key_blocks = util.parse_key_blocks(keys_text.decode("utf-8"))
    if release.committee is None:
        raise RuntimeError(f"Release {args.release_name} has no committee")
    for key_block in key_blocks:
        add_result = await interaction.key_user_add(None, key_block, [release.committee.name])
        _LOGGER.info(f"Added key block to user: {add_result}")
    return None
