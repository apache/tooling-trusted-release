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

"""worker.py - Task worker process for ATR"""

# TODO: If started is older than some threshold and status
# is active but the pid is no longer running, we can revert
# the task to status='QUEUED'. For this to work, ideally we
# need to check wall clock time as well as CPU time.

import asyncio
import datetime
import json
import logging
import os
import resource
import signal
import sys
import traceback
from typing import TYPE_CHECKING, Any, Final

import sqlmodel

import atr.db as db
import atr.db.models as models
import atr.tasks.bulk as bulk
import atr.tasks.checks as checks
import atr.tasks.checks.archive as archive
import atr.tasks.checks.hashing as hashing
import atr.tasks.checks.license as license
import atr.tasks.checks.rat as rat
import atr.tasks.checks.signature as signature
import atr.tasks.mailtest as mailtest
import atr.tasks.rsync as rsync
import atr.tasks.sbom as sbom
import atr.tasks.task as task
import atr.tasks.vote as vote

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

_LOGGER: Final = logging.getLogger(__name__)

# Resource limits, 5 minutes and 1GB
# _CPU_LIMIT_SECONDS: Final = 300
_MEMORY_LIMIT_BYTES: Final = 1024 * 1024 * 1024

# # Create tables if they don't exist
# SQLModel.metadata.create_all(engine)


def main() -> None:
    """Main entry point."""
    import atr.config as config

    signal.signal(signal.SIGTERM, _worker_signal_handle)
    signal.signal(signal.SIGINT, _worker_signal_handle)

    conf = config.get()
    if os.path.isdir(conf.STATE_DIR):
        os.chdir(conf.STATE_DIR)

    _setup_logging()

    _LOGGER.info(f"Starting worker process with pid {os.getpid()}")
    db.init_database_for_worker()

    _worker_resources_limit_set()
    asyncio.run(_worker_loop_run())


def _setup_logging() -> None:
    # Configure logging
    log_format = "[%(asctime)s.%(msecs)03d] [%(process)d] [%(levelname)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    logging.basicConfig(filename="atr-worker.log", format=log_format, datefmt=date_format, level=logging.INFO)


# Task functions


async def _task_error_handle(task_id: int, e: Exception) -> None:
    """Handle task error by updating the database with error information."""
    if isinstance(e, task.Error):
        _LOGGER.error(f"Task {task_id} failed: {e.message}")
        _LOGGER.error("".join(traceback.format_exception(e)))
        result = json.dumps(e.result)

        async with db.session() as data:
            async with data.begin():
                task_obj = await data.task(id=task_id).get()
                if task_obj:
                    task_obj.status = task.FAILED
                    task_obj.completed = datetime.datetime.now(datetime.UTC)
                    task_obj.error = e.message
                    task_obj.result = result
    else:
        _LOGGER.error(f"Task {task_id} failed: {e}")
        _LOGGER.error("".join(traceback.format_exception(e)))

        async with db.session() as data:
            async with data.begin():
                task_obj = await data.task(id=task_id).get()
                if task_obj:
                    task_obj.status = task.FAILED
                    task_obj.completed = datetime.datetime.now(datetime.UTC)
                    task_obj.error = str(e)


async def _task_next_claim() -> tuple[int, str, list[str] | dict[str, Any]] | None:
    """
    Attempt to claim the oldest unclaimed task.
    Returns (task_id, task_type, task_args) if successful.
    Returns None if no tasks are available.
    """
    async with db.session() as data:
        async with data.begin():
            # Get the ID of the oldest queued task
            oldest_queued_task = (
                sqlmodel.select(models.Task.id)
                .where(models.Task.status == task.QUEUED)
                .order_by(db.validate_instrumented_attribute(models.Task.added).asc())
                .limit(1)
            )

            # Use an UPDATE with a WHERE clause to atomically claim the task
            # This ensures that only one worker can claim a specific task
            now = datetime.datetime.now(datetime.UTC)
            update_stmt = (
                sqlmodel.update(models.Task)
                .where(sqlmodel.and_(models.Task.id == oldest_queued_task, models.Task.status == task.QUEUED))
                .values(status=task.ACTIVE, started=now, pid=os.getpid())
                .returning(
                    db.validate_instrumented_attribute(models.Task.id),
                    db.validate_instrumented_attribute(models.Task.task_type),
                    db.validate_instrumented_attribute(models.Task.task_args),
                )
            )

            result = await data.execute(update_stmt)
            claimed_task = result.first()

            if claimed_task:
                task_id, task_type, task_args = claimed_task
                _LOGGER.info(f"Claimed task {task_id} ({task_type}) with args {task_args}")
                return task_id, task_type, task_args

            return None


async def _task_result_process(
    task_id: int, task_results: tuple[Any, ...], status: models.TaskStatus, error: str | None = None
) -> None:
    """Process and store task results in the database."""
    async with db.session() as data:
        async with data.begin():
            # Find the task by ID
            task_obj = await data.task(id=task_id).get()
            if task_obj:
                # Update task properties
                task_obj.status = status
                task_obj.completed = datetime.datetime.now(datetime.UTC)
                task_obj.result = task_results

                if (status == task.FAILED) and error:
                    task_obj.error = error


async def _task_process(task_id: int, task_type: str, task_args: list[str] | dict[str, Any]) -> None:
    """Process a claimed task."""
    _LOGGER.info(f"Processing task {task_id} ({task_type}) with args {task_args}")
    try:
        # Map task types to their handler functions
        modern_task_handlers: dict[str, Callable[..., Awaitable[str | None]]] = {
            checks.function_key(archive.integrity): archive.integrity,
            checks.function_key(archive.structure): archive.structure,
            checks.function_key(hashing.check): hashing.check,
            checks.function_key(license.files): license.files,
            checks.function_key(license.headers): license.headers,
            checks.function_key(rat.check): rat.check,
            checks.function_key(signature.check): signature.check,
            checks.function_key(rsync.analyse): rsync.analyse,
        }
        # TODO: We should use a decorator to register these automatically
        dict_task_handlers = {
            "package_bulk_download": bulk.download,
        }
        # TODO: These are synchronous
        # We plan to convert these to async dict handlers
        list_task_handlers = {
            "generate_cyclonedx_sbom": sbom.generate_cyclonedx,
            "mailtest_send": mailtest.send,
            "vote_initiate": vote.initiate,
        }

        task_results: tuple[Any, ...]
        if task_type in modern_task_handlers:
            # NOTE: The other two branches below are deprecated
            # This is transitional code, which we will tidy up significantly
            handler = modern_task_handlers[task_type]
            try:
                handler_result = await handler(task_args)
                task_results = tuple()
                if handler_result is not None:
                    task_results = (handler_result,)
                status = task.COMPLETED
                error = None
            except Exception as e:
                task_results = tuple()
                status = task.FAILED
                error = str(e)
        elif isinstance(task_args, dict):
            dict_handler = dict_task_handlers.get(task_type)
            if not dict_handler:
                msg = f"Unknown task type: {task_type}"
                _LOGGER.error(msg)
                raise Exception(msg)
            status, error, task_results = await dict_handler(task_args)
        else:
            list_handler = list_task_handlers.get(task_type)
            if not list_handler:
                msg = f"Unknown task type: {task_type}"
                _LOGGER.error(msg)
                raise Exception(msg)
            status, error, task_results = list_handler(task_args)
        _LOGGER.info(f"Task {task_id} completed with status {status}, error {error}, results {task_results}")
        await _task_result_process(task_id, task_results, status, error)

    except Exception as e:
        await _task_error_handle(task_id, e)


# Worker functions


async def _worker_loop_run() -> None:
    """Main worker loop."""
    while True:
        try:
            task = await _task_next_claim()
            if task:
                task_id, task_type, task_args = task
                await _task_process(task_id, task_type, task_args)
                # Only process one task and then exit
                # This prevents memory leaks from accumulating
                break
            else:
                # No tasks available, wait 100ms before checking again
                await asyncio.sleep(0.1)
        except Exception:
            # TODO: Should probably be more robust about this
            _LOGGER.exception("Worker loop error")
            await asyncio.sleep(1)


def _worker_resources_limit_set() -> None:
    """Set CPU and memory limits for this process."""
    # # Set CPU time limit
    # try:
    #     resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_SECONDS, CPU_LIMIT_SECONDS))
    #     _LOGGER.info(f"Set CPU time limit to {CPU_LIMIT_SECONDS} seconds")
    # except ValueError as e:
    #     _LOGGER.warning(f"Could not set CPU time limit: {e}")

    # Set memory limit
    try:
        resource.setrlimit(resource.RLIMIT_AS, (_MEMORY_LIMIT_BYTES, _MEMORY_LIMIT_BYTES))
        _LOGGER.info(f"Set memory limit to {_MEMORY_LIMIT_BYTES} bytes")
    except ValueError as e:
        _LOGGER.warning(f"Could not set memory limit: {e}")


def _worker_signal_handle(signum: int, frame: object) -> None:
    """Handle termination signals gracefully."""
    # For RLIMIT_AS we'll generally get a SIGKILL
    # For RLIMIT_CPU we'll get a SIGXCPU, which we can catch
    _LOGGER.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)


if __name__ == "__main__":
    _LOGGER.info("Starting ATR worker...")
    print("Starting ATR worker...")
    try:
        main()
    except Exception as e:
        with open("atr-worker-error.log", "a") as f:
            f.write(f"{datetime.datetime.now(datetime.UTC)}: {e}\n")
            f.flush()
