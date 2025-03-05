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

"""Worker process manager."""

import asyncio
import logging
import os
import signal
import sys
from datetime import UTC, datetime
from io import TextIOWrapper

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from atr.db import get_session

# Configure logging
logging.basicConfig(
    format="[%(asctime)s.%(msecs)03d] [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Global debug flag to control worker process output capturing
global_worker_debug = False


class WorkerProcess:
    """Interface to control a worker process."""

    def __init__(self, process: asyncio.subprocess.Process, started: datetime):
        self.process = process
        self.started = started
        self.last_checked = started

    @property
    def pid(self) -> int | None:
        return self.process.pid

    async def is_running(self) -> bool:
        """Check if the process is still running."""
        if self.process.returncode is not None:
            # Process has already exited
            return False

        if not self.pid:
            # Process did not start
            return False

        try:
            os.kill(self.pid, 0)
            self.last_checked = datetime.now(UTC)
            return True
        except ProcessLookupError:
            # Process no longer exists
            return False
        except PermissionError:
            # Process exists but we don't have permission to signal it
            # This shouldn't happen in our case since we own the process
            logger.warning(f"Permission error checking process {self.pid}")
            return False


class WorkerManager:
    """Manager for a pool of worker processes."""

    def __init__(
        self,
        min_workers: int = 4,
        max_workers: int = 8,
        check_interval_seconds: float = 2.0,
        max_task_seconds: float = 300.0,
    ):
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.check_interval_seconds = check_interval_seconds
        self.max_task_seconds = max_task_seconds
        self.workers: dict[int, WorkerProcess] = {}
        self.running = False
        self.check_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the worker manager."""
        if self.running:
            return

        self.running = True
        logger.info("Starting worker manager in %s", os.getcwd())

        # Start initial workers
        for _ in range(self.min_workers):
            await self.spawn_worker()

        # Start monitoring task
        self.check_task = asyncio.create_task(self.monitor_workers())

    async def stop(self) -> None:
        """Stop all workers and the manager."""
        if not self.running:
            return

        self.running = False
        logger.info("Stopping worker manager")

        # Cancel monitoring task
        if self.check_task:
            self.check_task.cancel()
            try:
                await self.check_task
            except asyncio.CancelledError:
                ...

        # Stop all workers
        await self.stop_all_workers()

    async def stop_all_workers(self) -> None:
        """Stop all worker processes."""
        for worker in list(self.workers.values()):
            if worker.pid:
                try:
                    os.kill(worker.pid, signal.SIGTERM)
                except ProcessLookupError:
                    # The process may have already exited
                    ...
                except Exception as e:
                    logger.error(f"Error stopping worker {worker.pid}: {e}")

        # Wait for processes to exit
        for worker in list(self.workers.values()):
            try:
                await asyncio.wait_for(worker.process.wait(), timeout=5.0)
            except TimeoutError:
                if worker.pid:
                    try:
                        os.kill(worker.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        # The process may have already exited
                        ...
                    except Exception as e:
                        logger.error(f"Error force killing worker {worker.pid}: {e}")

        self.workers.clear()

    async def spawn_worker(self) -> None:
        """Spawn a new worker process."""
        if len(self.workers) >= self.max_workers:
            return

        try:
            # Get the absolute path to the project root (i.e. atr/..)
            abs_path = await asyncio.to_thread(os.path.abspath, __file__)
            project_root = os.path.dirname(os.path.dirname(abs_path))

            # Ensure PYTHONPATH includes our project root
            env = os.environ.copy()
            python_path = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = f"{project_root}:{python_path}" if python_path else project_root

            # Get absolute path to worker script
            worker_script = os.path.join(project_root, "atr", "worker.py")

            # Handle stdout and stderr based on debug setting
            stdout_target: int | TextIOWrapper = asyncio.subprocess.DEVNULL
            stderr_target: int | TextIOWrapper = asyncio.subprocess.DEVNULL

            # Generate a unique log file name for this worker if debugging is enabled
            log_file_path = None
            if global_worker_debug:
                timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
                log_file_name = f"worker_{timestamp}_{os.getpid()}.log"
                log_file_path = os.path.join(project_root, "state", log_file_name)

                # Open log file for writing
                log_file = await asyncio.to_thread(open, log_file_path, "w")
                stdout_target = log_file
                stderr_target = log_file
                logger.info(f"Worker output will be logged to {log_file_path}")

            # Start worker process with the updated environment
            # Use preexec_fn to create new process group
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                worker_script,
                stdout=stdout_target,
                stderr=stderr_target,
                env=env,
                preexec_fn=os.setsid,
            )

            worker = WorkerProcess(process, datetime.now(UTC))
            if worker.pid:
                self.workers[worker.pid] = worker
                logger.info(f"Started worker process {worker.pid}")
                if global_worker_debug and log_file_path:
                    logger.info(f"Worker {worker.pid} logs: {log_file_path}")
            else:
                logger.error("Failed to start worker process: No PID assigned")
                if global_worker_debug and isinstance(stdout_target, TextIOWrapper):
                    await asyncio.to_thread(stdout_target.close)
        except Exception as e:
            logger.error(f"Error spawning worker: {e}")

    async def monitor_workers(self) -> None:
        """Monitor worker processes and restart them if needed."""
        while self.running:
            try:
                await self.check_workers()
                await asyncio.sleep(self.check_interval_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in worker monitor: {e}")
                # TODO: How long should we wait before trying again?
                await asyncio.sleep(1.0)

    async def check_workers(self) -> None:
        """Check worker processes and restart if needed."""
        exited_workers = []

        # Check each worker first
        for pid, worker in list(self.workers.items()):
            # Check if process is running
            if not await worker.is_running():
                exited_workers.append(pid)
                logger.info(f"Worker {pid} has exited")
                continue

            # Check if worker has been processing its task for too long
            # This also stops tasks if they have indeed been running for too long
            if await self.check_task_duration(pid, worker):
                exited_workers.append(pid)

        # Remove exited workers
        for pid in exited_workers:
            self.workers.pop(pid, None)

        # # Check for active tasks
        # try:
        #     async with get_session() as session:
        #         result = await session.execute(
        #             text("""
        #                 SELECT COUNT(*)
        #                 FROM task
        #                 WHERE status = 'QUEUED'
        #             """)
        #         )
        #         queued_count = result.scalar()
        #         logger.info(f"Found {queued_count} queued tasks waiting for workers")
        # except Exception as e:
        #     logger.error(f"Error checking queued tasks: {e}")

        # Spawn new workers if needed
        await self.maintain_worker_pool()

        # Reset any tasks that were being processed by exited workers
        if exited_workers:
            await self.reset_broken_tasks(exited_workers)

    async def terminate_long_running_task(
        self, session: AsyncSession, worker: WorkerProcess, task_id: int, pid: int
    ) -> None:
        """
        Terminate a task that has been running for too long.
        Updates the task status and terminates the worker process.
        """
        try:
            # Mark the task as failed
            await session.execute(
                text("""
                    UPDATE task
                    SET status = 'FAILED', completed = :now, error = :error
                    WHERE id = :task_id
                    AND status = 'ACTIVE'
                """),
                {
                    "now": datetime.now(UTC),
                    "task_id": task_id,
                    "error": f"Task terminated after exceeding time limit of {self.max_task_seconds} seconds",
                },
            )
            if worker.pid:
                os.kill(worker.pid, signal.SIGTERM)
                logger.info(f"Worker {pid} terminated after processing task {task_id} for > {self.max_task_seconds}s")
        except ProcessLookupError:
            return
        except Exception as e:
            logger.error(f"Error stopping long-running worker {pid}: {e}")

    async def check_task_duration(self, pid: int, worker: WorkerProcess) -> bool:
        """
        Check if a worker has been processing its task for too long.
        Returns True if the worker has been terminated.
        """
        try:
            async with get_session() as session:
                async with session.begin():
                    result = await session.execute(
                        text("""
                            SELECT id, started FROM task
                            WHERE status = 'ACTIVE'
                            AND pid = :pid
                        """),
                        {"pid": pid},
                    )
                    task = result.first()
                    if not task or not task[1]:
                        return False

                    task_id, started = task
                    # Convert started to datetime if it's a string
                    if isinstance(started, str):
                        try:
                            started = datetime.fromisoformat(started.replace("Z", "+00:00"))
                        except ValueError:
                            logger.error(f"Could not parse started time '{started}' for task {task_id}")
                            return False

                    task_duration = (datetime.now(UTC) - started).total_seconds()
                    if task_duration > self.max_task_seconds:
                        await self.terminate_long_running_task(session, worker, task_id, pid)
                        return True

                    return False
        except Exception as e:
            logger.error(f"Error checking task duration for worker {pid}: {e}")
            # TODO: Return True? False? Maybe None would be more suitable, or propagate the error
            return True

    async def maintain_worker_pool(self) -> None:
        """Ensure we maintain the minimum number of workers."""
        current_count = len(self.workers)
        if current_count < self.min_workers:
            logger.info(f"Worker pool below minimum ({current_count} < {self.min_workers}), spawning new workers")
            while len(self.workers) < self.min_workers:
                await self.spawn_worker()
            logger.info(f"Worker pool restored to {len(self.workers)} workers")

    async def reset_broken_tasks(self, exited_pids: list[int]) -> None:
        """Reset any tasks that were being processed by exited workers."""
        try:
            async with get_session() as session:
                async with session.begin():
                    # Generate named parameters for each PID
                    placeholders = ",".join(f":pid_{i}" for i in range(len(exited_pids)))
                    params = {f"pid_{i}": pid for i, pid in enumerate(exited_pids)}

                    # Execute update with proper parameter binding
                    await session.execute(
                        text(f"""
                            UPDATE task
                            SET status = 'QUEUED', started = NULL, pid = NULL
                            WHERE status = 'ACTIVE'
                            AND pid IN ({placeholders})
                        """),
                        params,
                    )
        except Exception as e:
            logger.error(f"Error resetting broken tasks: {e}")


# Global worker manager instance
worker_manager: WorkerManager | None = None


def get_worker_manager() -> WorkerManager:
    """Get the global worker manager instance."""
    global worker_manager
    if worker_manager is None:
        worker_manager = WorkerManager()
    return worker_manager
