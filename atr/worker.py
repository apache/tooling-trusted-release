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
import logging
import os
import resource
import signal
import sys
import time
from datetime import UTC
from typing import NoReturn

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

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

# Create database engine
engine = create_engine("sqlite:///atr.db", echo=False)

# # Create tables if they don't exist
# SQLModel.metadata.create_all(engine)


def get_db_session() -> Session:
    """Get a new database session."""
    return Session(engine)


def claim_next_task() -> tuple[int, str, str] | None:
    """
    Attempt to claim the oldest unclaimed task.
    Returns (task_id, task_type, task_args) if successful.
    Returns None if no tasks are available.
    """
    with get_db_session() as session:
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


def process_task(task_id: int, task_type: str, task_args: str) -> None:
    """Process a claimed task."""
    logger.info(f"Processing task {task_id} ({task_type}) with args {task_args}")
    try:
        # TODO: Implement actual task processing
        time.sleep(1)

        with get_db_session() as session:
            with session.begin():
                session.execute(
                    text("""
                        UPDATE task
                        SET completed = :now, status = 'COMPLETED'
                        WHERE id = :task_id
                        """),
                    {"now": datetime.datetime.now(UTC), "task_id": task_id},
                )
    except Exception as e:
        logger.error(f"Task {task_id} failed: {e}")
        with get_db_session() as session:
            with session.begin():
                session.execute(
                    text("""
                        UPDATE task
                        SET completed = :now, status = 'FAILED', error = :error
                        WHERE id = :task_id
                        """),
                    {"now": datetime.datetime.now(UTC), "task_id": task_id, "error": str(e)},
                )


def set_resource_limits() -> None:
    """Set CPU and memory limits for this process."""
    # Set CPU time limit
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_SECONDS, CPU_LIMIT_SECONDS))
        logger.info(f"Set CPU time limit to {CPU_LIMIT_SECONDS} seconds")
    except ValueError as e:
        logger.warning(f"Could not set CPU time limit: {e}")

    # Set memory limit
    try:
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT_BYTES, MEMORY_LIMIT_BYTES))
        logger.info(f"Set memory limit to {MEMORY_LIMIT_BYTES} bytes")
    except ValueError as e:
        logger.warning(f"Could not set memory limit: {e}")


def worker_loop() -> NoReturn:
    """Main worker loop."""
    logger.info(f"Worker starting (PID: {os.getpid()})")

    while True:
        try:
            task = claim_next_task()
            if task:
                task_id, task_type, task_args = task
                process_task(task_id, task_type, task_args)
            else:
                # No tasks available, wait 20ms before checking again
                time.sleep(0.02)
        except Exception as e:
            # TODO: Should probably be more robust about this
            logger.error(f"Worker loop error: {e}")
            time.sleep(1)


def signal_handler(signum: int, frame: object) -> None:
    """Handle termination signals gracefully."""
    # For RLIMIT_AS we'll generally get a SIGKILL
    # For RLIMIT_CPU we'll get a SIGXCPU, which we can catch
    logger.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)


def main() -> None:
    """Main entry point."""
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    set_resource_limits()
    worker_loop()


if __name__ == "__main__":
    main()
