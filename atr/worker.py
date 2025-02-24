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

import datetime
import json
import logging
import os
import resource
import signal
import sys
import time
from datetime import UTC
from typing import Any

from sqlalchemy import text

import atr.verify as verify

# Configure logging
logging.basicConfig(
    format="[%(asctime)s.%(msecs)03d] [%(process)d] [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Resource limits, 5 minutes and 1GB
CPU_LIMIT_SECONDS = 300
MEMORY_LIMIT_BYTES = 1024 * 1024 * 1024

# # Create tables if they don't exist
# SQLModel.metadata.create_all(engine)


def main() -> None:
    """Main entry point."""
    signal.signal(signal.SIGTERM, worker_signal_handle)
    signal.signal(signal.SIGINT, worker_signal_handle)

    worker_resources_limit_set()
    worker_loop_run()


# Task functions


def task_error_handle(task_id: int, e: Exception) -> None:
    """Handle task error by updating the database with error information."""
    if isinstance(e, verify.VerifyError):
        logger.error(f"Task {task_id} failed: {e.message}")
        result = json.dumps(e.result)
        with verify.db_session_get() as session:
            with session.begin():
                session.execute(
                    text("""
                        UPDATE task
                        SET status = 'FAILED', completed = :now, error = :error, result = :result
                        WHERE id = :task_id
                        """),
                    {"now": datetime.datetime.now(UTC), "task_id": task_id, "error": e.message, "result": result},
                )
    else:
        logger.error(f"Task {task_id} failed: {e}")
        with verify.db_session_get() as session:
            with session.begin():
                session.execute(
                    text("""
                        UPDATE task
                        SET status = 'FAILED', completed = :now, error = :error
                        WHERE id = :task_id
                        """),
                    {"now": datetime.datetime.now(UTC), "task_id": task_id, "error": str(e)},
                )


def task_next_claim() -> tuple[int, str, str] | None:
    """
    Attempt to claim the oldest unclaimed task.
    Returns (task_id, task_type, task_args) if successful.
    Returns None if no tasks are available.
    """
    with verify.db_session_get() as session:
        with session.begin():
            # Find and claim the oldest unclaimed task
            # We have an index on (status, added)
            result = session.execute(
                text("""
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
                {"now": datetime.datetime.now(UTC), "pid": os.getpid()},
            )
            task = result.first()
            if task:
                task_id, task_type, task_args = task
                logger.info(f"Claimed task {task_id} ({task_type}) with args {task_args}")
                return task_id, task_type, task_args

            return None


def task_result_process(
    task_id: int, task_results: tuple[Any, ...], status: str = "COMPLETED", error: str | None = None
) -> None:
    """Process and store task results in the database."""
    with verify.db_session_get() as session:
        result = json.dumps(task_results)
        with session.begin():
            if status == "FAILED" and error:
                session.execute(
                    text("""
                        UPDATE task
                        SET status = :status, completed = :now, result = :result, error = :error
                        WHERE id = :task_id
                        """),
                    {
                        "now": datetime.datetime.now(UTC),
                        "task_id": task_id,
                        "result": result,
                        "status": status,
                        "error": error,
                    },
                )
            else:
                session.execute(
                    text("""
                        UPDATE task
                        SET status = :status, completed = :now, result = :result
                        WHERE id = :task_id
                        """),
                    {"now": datetime.datetime.now(UTC), "task_id": task_id, "result": result, "status": status},
                )


def task_process(task_id: int, task_type: str, task_args: str) -> None:
    """Process a claimed task."""
    logger.info(f"Processing task {task_id} ({task_type}) with args {task_args}")
    try:
        status = "COMPLETED"
        error = None
        args = json.loads(task_args)

        if task_type == "verify_archive_integrity":
            task_results = task_process_wrap(verify.archive_integrity(*args))
            logger.info(f"Verified {args} and computed size {task_results[0]}")
        elif task_type == "verify_archive_structure":
            task_results = task_process_wrap(verify.archive_structure(*args))
            logger.info(f"Verified archive structure for {args}")
            if not task_results[0]["valid"]:
                status = "FAILED"
                error = task_results[0]["message"]
        elif task_type == "verify_license_files":
            task_results = task_process_wrap(verify.license_files(*args))
            logger.info(f"Verified license files for {args}")
            if not task_results[0]["files_found"]:
                status = "FAILED"
                error = "Required license files not found"
        elif task_type == "verify_signature":
            task_results = task_process_wrap(verify.signature(*args))
            logger.info(f"Verified {args} with result {task_results[0]}")
            if task_results[0]["error"]:
                status = "FAILED"
        else:
            error = f"Unknown task type: {task_type}"
            logger.error(error)
            raise Exception(error)

        task_result_process(task_id, task_results, status, error)

    except Exception as e:
        task_error_handle(task_id, e)


def task_process_wrap(item: Any) -> tuple[Any, ...]:
    """Ensure that returned results are structured as a tuple."""
    if not isinstance(item, tuple):
        return (item,)
    return item


# Worker functions


def worker_loop_run() -> None:
    """Main worker loop."""
    if os.path.isdir("state"):
        os.chdir("state")

    while True:
        try:
            task = task_next_claim()
            if task:
                task_id, task_type, task_args = task
                task_process(task_id, task_type, task_args)
                # Only process one task and then exit
                # This prevents memory leaks from accumulating
                break
            else:
                # No tasks available, wait 20ms before checking again
                time.sleep(0.02)
        except Exception as e:
            # TODO: Should probably be more robust about this
            logger.error(f"Worker loop error: {e}")
            time.sleep(1)


def worker_resources_limit_set() -> None:
    """Set CPU and memory limits for this process."""
    # # Set CPU time limit
    # try:
    #     resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_SECONDS, CPU_LIMIT_SECONDS))
    #     logger.info(f"Set CPU time limit to {CPU_LIMIT_SECONDS} seconds")
    # except ValueError as e:
    #     logger.warning(f"Could not set CPU time limit: {e}")

    # Set memory limit
    try:
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT_BYTES, MEMORY_LIMIT_BYTES))
        logger.info(f"Set memory limit to {MEMORY_LIMIT_BYTES} bytes")
    except ValueError as e:
        logger.warning(f"Could not set memory limit: {e}")


def worker_signal_handle(signum: int, frame: object) -> None:
    """Handle termination signals gracefully."""
    # For RLIMIT_AS we'll generally get a SIGKILL
    # For RLIMIT_CPU we'll get a SIGXCPU, which we can catch
    logger.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        with open("atr-worker-error.log", "a") as f:
            f.write(f"{datetime.datetime.now(UTC)}: {e}\n")
            f.flush()
