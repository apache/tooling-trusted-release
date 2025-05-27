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

from __future__ import annotations

import asyncio
import datetime
import io
import logging
import os
import signal
import sys
from typing import Final

import sqlmodel

import atr.db as db
import atr.db.models as models

_LOGGER: Final = logging.getLogger(__name__)

# Global debug flag to control worker process output capturing
global_worker_debug: bool = False

# Global worker manager instance
# Can't use "StringClass" | None, must use Optional["StringClass"] for forward references
global_worker_manager: WorkerManager | None = None


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
        _LOGGER.info("Starting worker manager in %s", os.getcwd())

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
        _LOGGER.info("Stopping worker manager")

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
                    _LOGGER.error(f"Error stopping worker {worker.pid}: {e}")

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
                        _LOGGER.error(f"Error force killing worker {worker.pid}: {e}")

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
            stdout_target: int | io.TextIOWrapper = asyncio.subprocess.DEVNULL
            stderr_target: int | io.TextIOWrapper = asyncio.subprocess.DEVNULL

            # Generate a unique log file name for this worker if debugging is enabled
            log_file_path = None
            if global_worker_debug:
                timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d_%H%M%S")
                log_file_name = f"worker_{timestamp}_{os.getpid()}.log"
                log_file_path = os.path.join(project_root, "state", log_file_name)

                # Open log file for writing
                log_file = await asyncio.to_thread(open, log_file_path, "w")
                stdout_target = log_file
                stderr_target = log_file
                _LOGGER.info(f"Worker output will be logged to {log_file_path}")

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

            worker = WorkerProcess(process, datetime.datetime.now(datetime.UTC))
            if worker.pid:
                self.workers[worker.pid] = worker
                _LOGGER.info(f"Started worker process {worker.pid}")
                if global_worker_debug and log_file_path:
                    _LOGGER.info(f"Worker {worker.pid} logs: {log_file_path}")
            else:
                _LOGGER.error("Failed to start worker process: No PID assigned")
                if global_worker_debug and isinstance(stdout_target, io.TextIOWrapper):
                    await asyncio.to_thread(stdout_target.close)
        except Exception as e:
            _LOGGER.error(f"Error spawning worker: {e}")

    async def monitor_workers(self) -> None:
        """Monitor worker processes and restart them if needed."""
        while self.running:
            try:
                await self.check_workers()
                await asyncio.sleep(self.check_interval_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:
                _LOGGER.error(f"Error in worker monitor: {e}", exc_info=e)
                # TODO: How long should we wait before trying again?
                await asyncio.sleep(1.0)

    async def check_workers(self) -> None:
        """Check worker processes and restart if needed."""
        exited_workers = []

        async with db.session() as data:
            # Check each worker first
            for pid, worker in list(self.workers.items()):
                # Check if process is running
                if not await worker.is_running():
                    exited_workers.append(pid)
                    _LOGGER.info(f"Worker {pid} has exited")
                    continue

                # Check if worker has been processing its task for too long
                # This also stops tasks if they have indeed been running for too long
                if await self.check_task_duration(data, pid, worker):
                    exited_workers.append(pid)

        # Remove exited workers
        for pid in exited_workers:
            self.workers.pop(pid, None)

        # Check for active tasks
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

        # Reset any tasks that were being processed by now inactive workers
        await self.reset_broken_tasks()

    async def terminate_long_running_task(
        self, task: models.Task, worker: WorkerProcess, task_id: int, pid: int
    ) -> None:
        """
        Terminate a task that has been running for too long.
        Updates the task status and terminates the worker process.
        """
        try:
            # Mark the task as failed
            task.status = models.TaskStatus.FAILED
            task.completed = datetime.datetime.now(datetime.UTC)
            task.error = f"Task terminated after exceeding time limit of {self.max_task_seconds} seconds"

            if worker.pid:
                os.kill(worker.pid, signal.SIGTERM)
                _LOGGER.info(f"Worker {pid} terminated after processing task {task_id} for > {self.max_task_seconds}s")
        except ProcessLookupError:
            return
        except Exception as e:
            _LOGGER.error(f"Error stopping long-running worker {pid}: {e}")

    async def check_task_duration(self, data: db.Session, pid: int, worker: WorkerProcess) -> bool:
        """
        Check whether a worker has been processing its task for too long.
        Returns True if the worker has been terminated.
        """
        try:
            async with data.begin():
                task = await data.task(pid=pid, status=models.TaskStatus.ACTIVE).get()
                if not task or not task.started:
                    return False

                task_duration = (datetime.datetime.now(datetime.UTC) - task.started).total_seconds()
                if task_duration > self.max_task_seconds:
                    await self.terminate_long_running_task(task, worker, task.id, pid)
                    return True

                return False
        except Exception as e:
            _LOGGER.error(f"Error checking task duration for worker {pid}: {e}")
            # TODO: Return False here to avoid over-reporting errors
            return False

    async def maintain_worker_pool(self) -> None:
        """Ensure we maintain the minimum number of workers."""
        current_count = len(self.workers)
        if current_count < self.min_workers:
            _LOGGER.info(f"Worker pool below minimum ({current_count} < {self.min_workers}), spawning new workers")
            while len(self.workers) < self.min_workers:
                await self.spawn_worker()
            _LOGGER.info(f"Worker pool restored to {len(self.workers)} workers")

    async def _log_tasks_held_by_unmanaged_pids(self, data: db.Session, active_worker_pids: list[int]) -> None:
        """Log tasks that are active and held by PIDs not managed by this worker manager."""
        foreign_tasks_stmt = sqlmodel.select(models.Task.pid, models.Task.id).where(
            sqlmodel.and_(
                models.validate_instrumented_attribute(models.Task.pid).notin_(active_worker_pids),
                models.Task.status == models.TaskStatus.ACTIVE,
                models.validate_instrumented_attribute(models.Task.pid).isnot(None),
            )
        )
        foreign_tasks_result = await data.execute(foreign_tasks_stmt)
        foreign_pids_with_tasks: dict[int, int] = {
            row.pid: row.id for row in foreign_tasks_result if row.pid is not None
        }

        if not foreign_pids_with_tasks:
            return

        _LOGGER.debug(f"Found tasks potentially claimed by non-managed PIDs: {foreign_pids_with_tasks}")
        for foreign_pid, task_id_held in foreign_pids_with_tasks.items():
            try:
                os.kill(foreign_pid, 0)
                _LOGGER.warning(f"Task {task_id_held} is held by an active, unmanaged process (PID: {foreign_pid})")
            except ProcessLookupError:
                _LOGGER.info(f"Task {task_id_held} was held by PID {foreign_pid}, which is no longer running")
            except Exception as e:
                _LOGGER.error(f"Unexpected error: {foreign_pid} holding task {task_id_held}: {e}")

    async def reset_broken_tasks(self) -> None:
        """Reset any tasks that were being processed by exited or unmanaged workers."""
        try:
            async with db.session() as data:
                async with data.begin():
                    active_worker_pids = list(self.workers)
                    try:
                        await self._log_tasks_held_by_unmanaged_pids(data, active_worker_pids)
                    except Exception:
                        ...

                    update_stmt = (
                        sqlmodel.update(models.Task)
                        .where(
                            sqlmodel.and_(
                                models.validate_instrumented_attribute(models.Task.pid).notin_(active_worker_pids),
                                models.Task.status == models.TaskStatus.ACTIVE,
                            )
                        )
                        .values(status=models.TaskStatus.QUEUED, started=None, pid=None)
                    )

                    result = await data.execute(update_stmt)
                    if result.rowcount > 0:
                        _LOGGER.info(f"Reset {result.rowcount} tasks to state 'QUEUED' due to worker issues")

        except Exception as e:
            _LOGGER.error(f"Error resetting broken tasks: {e}")


class WorkerProcess:
    """Interface to control a worker process."""

    def __init__(self, process: asyncio.subprocess.Process, started: datetime.datetime):
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
            self.last_checked = datetime.datetime.now(datetime.UTC)
            return True
        except ProcessLookupError:
            # Process no longer exists
            return False
        except PermissionError:
            # Process exists, but we don't have permission to signal it
            # This shouldn't happen in our case since we own the process
            _LOGGER.warning(f"Permission error checking process {self.pid}")
            return False


def get_worker_manager() -> WorkerManager:
    """Get the global worker manager instance."""
    global global_worker_manager
    if global_worker_manager is None:
        global_worker_manager = WorkerManager()
    return global_worker_manager
