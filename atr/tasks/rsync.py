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
from typing import TYPE_CHECKING, Any, Final

import aiofiles.os
import pydantic

import atr.db as db
import atr.db.models as models
import atr.tasks as tasks
import atr.tasks.task as task
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

# _CONFIG: Final = config.get()
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
    base_path = util.get_release_candidate_draft_dir() / project_name / release_version
    paths = await util.paths_recursive(base_path)
    release_name = f"{project_name}-{release_version}"

    async with db.session() as data:
        release = await data.release(name=release_name, _committee=True).demand(RuntimeError("Release not found"))
        for path in paths:
            # This works because path is relative
            full_path = base_path / path

            # We only want to analyse files that are new or have changed
            # But rsync can set timestamps to the past, so we can't rely on them
            # Instead, we can run any tasks when the file has a different modified time
            # TODO: This may cause problems if the file is backdated
            modified = int(await aiofiles.os.path.getmtime(full_path))
            cached_tasks = await db.recent_tasks(data, release_name, str(path), modified)

            # Add new tasks for each path
            task_functions: dict[str, Callable[..., Coroutine[Any, Any, list[models.Task]]]] = {
                ".asc": tasks.asc_checks,
                ".sha256": tasks.sha_checks,
                ".sha512": tasks.sha_checks,
                ".tar.gz": tasks.tar_gz_checks,
            }
            for task_type, task_function in task_functions.items():
                if path.name.endswith(task_type):
                    for task in await task_function(release, str(path)):
                        if task.task_type not in cached_tasks:
                            data.add(task)
        await data.commit()
    return {"paths": [str(path) for path in paths]}
