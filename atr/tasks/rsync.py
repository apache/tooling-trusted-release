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
import atr.tasks.checks as checks

# import atr.tasks.checks.paths as paths
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

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
        result_data = await _analyse_core(
            args.project_name,
            args.release_version,
        )
        num_paths = len(result_data.get("paths", []))
        _LOGGER.info(f"Finished rsync analysis for {args.project_name} {args.release_version}, found {num_paths} paths")
    except Exception as e:
        _LOGGER.exception(f"Rsync analysis failed for {args.project_name} {args.release_version}: {e}")
        raise e

    return None


async def _analyse_core(project_name: str, release_version: str) -> dict[str, Any]:
    """Core logic to analyse an rsync upload and queue checks."""
    base_path = util.get_release_candidate_draft_dir() / project_name / release_version
    paths_recursive = await util.paths_recursive(base_path)
    release_name = f"{project_name}-{release_version}"

    async with db.session() as data:
        release = await data.release(name=release_name, _committee=True).demand(RuntimeError("Release not found"))
        for path in paths_recursive:
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

            # # Add the generic path check task for every file
            # if path_check_task_key not in cached_tasks:
            #     path_check_task_args = paths.Check(
            #         release_name=release_name,
            #         base_release_dir=str(base_path),
            #         path=str(path),
            #     ).model_dump()

        #     path_check_task = models.Task(
        #         status=models.TaskStatus.QUEUED,
        #         task_type=tasks.Type.PATHS_CHECK,
        #         task_args=paths.Check(
        #             release_name=release_name,
        #             base_release_dir=str(base_path),
        #             path=str(path),
        #         ).model_dump(),
        #     )

        await data.commit()
    return {"paths": [str(path) for path in paths_recursive]}
