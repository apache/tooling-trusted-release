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
import os
from typing import Any, Final

import pydantic

import atr.config as config
import atr.db.models as models
import atr.tasks.task as task
import atr.util as util

_CONFIG: Final = config.get()
_LOGGER: Final = logging.getLogger(__name__)


class Analyse(pydantic.BaseModel):
    """Parameters for rsync analysis."""

    asf_uid: str = pydantic.Field(..., description="ASF UID of the user to rsync from")
    project_name: str = pydantic.Field(..., description="Name of the project to rsync")
    release_version: str = pydantic.Field(..., description="Version of the release to rsync")


async def analyse(args: dict[str, Any]) -> tuple[models.TaskStatus, str | None, tuple[Any, ...]]:
    """Analyse an rsync upload."""
    data = Analyse(**args)
    task_results = task.results_as_tuple(
        await _analyse_core(
            data.asf_uid,
            data.project_name,
            data.release_version,
        )
    )
    _LOGGER.info(f"Analyse {data.project_name} {data.release_version}")
    return task.COMPLETED, None, task_results


async def _analyse_core(asf_uid: str, project_name: str, release_version: str) -> dict[str, Any]:
    """Analyse an rsync upload."""
    base_path = os.path.join(_CONFIG.STATE_DIR, "rsync-files", project_name, release_version)
    paths = await util.paths_recursive(base_path)
    # for path in paths:
    #     # Add new tasks for each path
    #     # We could use the SHA3 in input and output
    #     # Or, less securely, we could use path and mtime instead
    #     ...
    return {"paths": paths}
