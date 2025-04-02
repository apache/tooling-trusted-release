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

import pydantic

import atr.tasks as tasks
import atr.tasks.checks as checks

# _CONFIG: Final = config.get()
_LOGGER: Final = logging.getLogger(__name__)


class Analyse(pydantic.BaseModel):
    """Parameters for rsync analysis."""

    project_name: str = pydantic.Field(..., description="Name of the project to rsync")
    release_version: str = pydantic.Field(..., description="Version of the release to rsync")


@checks.with_model(Analyse)
async def analyse(args: Analyse) -> str | None:
    """Analyse an rsync upload by queuing specific checks for discovered files."""
    _LOGGER.info(f"Starting rsync analysis for {args.project_name} {args.release_version}")
    try:
        num_paths = await tasks.draft_checks(
            args.project_name,
            args.release_version,
        )
        _LOGGER.info(f"Finished rsync analysis for {args.project_name} {args.release_version}, found {num_paths} paths")
    except Exception as e:
        _LOGGER.exception(f"Rsync analysis failed for {args.project_name} {args.release_version}: {e}")
        raise e

    return None
