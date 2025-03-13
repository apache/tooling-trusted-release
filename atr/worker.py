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
from typing import Any, Final

import sqlalchemy

import atr.db as db
import atr.tasks.archive as archive
import atr.tasks.bulk as bulk
import atr.tasks.license as license
import atr.tasks.mailtest as mailtest
import atr.tasks.rat as rat
import atr.tasks.sbom as sbom
import atr.tasks.signature as signature
import atr.tasks.task as task
import atr.tasks.vote as vote

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
        result = json.dumps(e.result)
        async with db.create_async_db_session() as session:
            async with session.begin():
                await session.execute(
                    sqlalchemy.text("""
                        UPDATE task
                        SET status = 'FAILED', completed = :now, error = :error, result = :result
                        WHERE id = :task_id
                        """),
                    {
                        "now": datetime.datetime.now(datetime.UTC),
                        "task_id": task_id,
                        "error": e.message,
                        "result": result,
                    },
                )
    else:
        _LOGGER.error(f"Task {task_id} failed: {e}")
        async with db.create_async_db_session() as session:
            async with session.begin():
                await session.execute(
                    sqlalchemy.text("""
                        UPDATE task
                        SET status = 'FAILED', completed = :now, error = :error
                        WHERE id = :task_id
                        """),
                    {"now": datetime.datetime.now(datetime.UTC), "task_id": task_id, "error": str(e)},
                )


async def _task_next_claim() -> tuple[int, str, str] | None:
    """
    Attempt to claim the oldest unclaimed task.
    Returns (task_id, task_type, task_args) if successful.
    Returns None if no tasks are available.
    """
    async with db.create_async_db_session() as session:
        async with session.begin():
            # Find and claim the oldest unclaimed task
            # We have an index on (status, added)
            result = await session.execute(
                sqlalchemy.text("""
                    UPDATE task
                    SET started = :now, pid = :pid, status = 'ACTIVE'
                    WHERE id = (
                        SELECT id FROM task
                        WHERE status = 'QUEUED'
                        ORDER BY added ASC LIMIT 1
                    )
                    AND status = 'QUEUED'
                    RETURNING id, task_type, task_args
                    """),
                {"now": datetime.datetime.now(datetime.UTC), "pid": os.getpid()},
            )
            task = result.first()
            if task:
                task_id, task_type, task_args = task
                _LOGGER.info(f"Claimed task {task_id} ({task_type}) with args {task_args}")
                return task_id, task_type, task_args

            return None


async def _task_result_process(
    task_id: int, task_results: tuple[Any, ...], status: str = "COMPLETED", error: str | None = None
) -> None:
    """Process and store task results in the database."""
    async with db.create_async_db_session() as session:
        result = json.dumps(task_results)
        async with session.begin():
            if status == "FAILED" and error:
                await session.execute(
                    sqlalchemy.text("""
                        UPDATE task
                        SET status = :status, completed = :now, result = :result, error = :error
                        WHERE id = :task_id
                        """),
                    {
                        "now": datetime.datetime.now(datetime.UTC),
                        "task_id": task_id,
                        "result": result,
                        "status": status.upper(),
                        "error": error,
                    },
                )
            else:
                await session.execute(
                    sqlalchemy.text("""
                        UPDATE task
                        SET status = :status, completed = :now, result = :result
                        WHERE id = :task_id
                        """),
                    {
                        "now": datetime.datetime.now(datetime.UTC),
                        "task_id": task_id,
                        "result": result,
                        "status": status.upper(),
                    },
                )


async def _task_process(task_id: int, task_type: str, task_args: str) -> None:
    """Process a claimed task."""
    _LOGGER.info(f"Processing task {task_id} ({task_type}) with args {task_args}")
    try:
        args = json.loads(task_args)

        # Map task types to their handler functions
        # TODO: We should use a decorator to register these automatically
        dict_task_handlers = {
            "verify_archive_integrity": archive.check_integrity,
            "package_bulk_download": bulk.download,
        }
        # TODO: These are synchronous
        # We plan to convert these to async dict handlers
        list_task_handlers = {
            "verify_archive_structure": archive.check_structure,
            "verify_license_files": license.check_files,
            "verify_signature": signature.check,
            "verify_license_headers": license.check_headers,
            "verify_rat_license": rat.check_licenses,
            "generate_cyclonedx_sbom": sbom.generate_cyclonedx,
            "mailtest_send": mailtest.send,
            "vote_initiate": vote.initiate,
        }

        if isinstance(args, dict):
            dict_handler = dict_task_handlers.get(task_type)
            if not dict_handler:
                msg = f"Unknown task type: {task_type}"
                _LOGGER.error(msg)
                raise Exception(msg)
            status, error, task_results = await dict_handler(args)
        else:
            list_handler = list_task_handlers.get(task_type)
            if not list_handler:
                msg = f"Unknown task type: {task_type}"
                _LOGGER.error(msg)
                raise Exception(msg)
            status, error, task_results = list_handler(args)

        await _task_result_process(task_id, task_results, status=status.value.upper(), error=error)

    except Exception as e:
        await _task_error_handle(task_id, e)


async def _task_process_wrap(item: Any) -> tuple[Any, ...]:
    """Ensure that returned results are structured as a tuple."""
    if not isinstance(item, tuple):
        return (item,)
    return item


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
