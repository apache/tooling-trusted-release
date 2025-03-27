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

from __future__ import annotations

import asyncio
import functools
import logging
import time
from typing import TYPE_CHECKING, Any, Final, NoReturn, ParamSpec, Protocol, TypeVar

import aiofiles
import aiofiles.os
import asfquart
import asfquart.auth as auth
import asfquart.base as base
import asfquart.session as session
import quart

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Coroutine

    import werkzeug.datastructures as datastructures

import atr.db.models as models
import atr.user as user

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")

P = ParamSpec("P")
T = TypeVar("T")

# TODO: Should get this from config, checking debug there
measure_performance: bool = True

_LOGGER: Final = logging.getLogger(__name__)

# |         1 | RSA (Encrypt or Sign) [HAC]                        |
# |         2 | RSA Encrypt-Only [HAC]                             |
# |         3 | RSA Sign-Only [HAC]                                |
# |        16 | Elgamal (Encrypt-Only) [ELGAMAL] [HAC]             |
# |        17 | DSA (Digital Signature Algorithm) [FIPS186] [HAC]  |
# |        18 | ECDH public key algorithm                          |
# |        19 | ECDSA public key algorithm [FIPS186]               |
# |        20 | Reserved (formerly Elgamal Encrypt or Sign)        |
# |        21 | Reserved for Diffie-Hellman                        |
# |           | (X9.42, as defined for IETF-S/MIME)                |
# |        22 | EdDSA [I-D.irtf-cfrg-eddsa]                        |
# - https://lists.gnupg.org/pipermail/gnupg-devel/2017-April/032762.html
# TODO: (Obviously we should move this, but where to?)
algorithms: Final[dict[int, str]] = {
    1: "RSA",
    2: "RSA",
    3: "RSA",
    16: "Elgamal",
    17: "DSA",
    18: "ECDH",
    19: "ECDSA",
    21: "Diffie-Hellman",
    22: "EdDSA",
}


class FlashError(RuntimeError): ...


class MicrosecondsFormatter(logging.Formatter):
    # Answers on a postcard if you know why Python decided to use a comma by default
    default_msec_format = "%s.%03d"


class AsyncFileHandler(logging.Handler):
    """A logging handler that writes logs asynchronously using aiofiles."""

    def __init__(self, filename, mode="w", encoding=None):
        super().__init__()
        self.filename = filename

        if mode != "w":
            raise RuntimeError("Only write mode is supported")

        self.encoding = encoding
        self.queue = asyncio.Queue()
        self.our_worker_task = None

    def our_worker_task_ensure(self):
        """Lazily create the worker task if it doesn't exist and there's an event loop."""
        if self.our_worker_task is None:
            try:
                loop = asyncio.get_running_loop()
                self.our_worker_task = loop.create_task(self.our_worker())
            except RuntimeError:
                # No event loop running yet, try again on next emit
                ...

    async def our_worker(self):
        """Background task that writes queued log messages to file."""
        # Use a binary mode literal with aiofiles.open
        # https://github.com/Tinche/aiofiles/blob/main/src/aiofiles/threadpool/__init__.py
        # We should be able to use any mode, but pyright requires a binary mode
        async with aiofiles.open(self.filename, "wb+") as f:
            while True:
                record = await self.queue.get()
                if record is None:
                    break

                try:
                    # Format the log record first
                    formatted_message = self.format(record) + "\n"
                    message_bytes = formatted_message.encode(self.encoding or "utf-8")
                    await f.write(message_bytes)
                    await f.flush()
                except Exception:
                    self.handleError(record)
                finally:
                    self.queue.task_done()

    def emit(self, record):
        """Queue the record for writing by the worker task."""
        try:
            # Ensure worker task is running
            self.our_worker_task_ensure()

            # Queue the record, but handle the case where no event loop is running yet
            try:
                self.queue.put_nowait(record)
            except RuntimeError:
                ...
        except Exception:
            self.handleError(record)

    def close(self):
        """Shut down the worker task cleanly."""
        if self.our_worker_task is not None and not self.our_worker_task.done():
            try:
                self.queue.put_nowait(None)
            except RuntimeError:
                # No running event loop, no need to clean up
                ...
        super().close()


# Setup a dedicated logger for route performance metrics
route_logger = logging.getLogger("route.performance")
# Use custom formatter that properly includes microseconds
# TODO: Is this actually UTC?
route_logger_handler = AsyncFileHandler("route-performance.log")
route_logger_handler.setFormatter(MicrosecondsFormatter("%(asctime)s - %(message)s"))
route_logger.addHandler(route_logger_handler)
route_logger.setLevel(logging.INFO)
# If we don't set propagate to False then it logs to the term as well
route_logger.propagate = False


def app_route(path: str, methods: list[str] | None = None, endpoint: str | None = None) -> Callable:
    """Register a route with the Flask app with built-in performance logging."""

    def decorator(f: Callable[P, Coroutine[Any, Any, T]]) -> Callable[P, Awaitable[T]]:
        # First apply our performance measuring decorator
        if measure_performance:
            measured_func = app_route_performance_measure(path, methods)(f)
        else:
            measured_func = f
        # Then apply the original route decorator
        return asfquart.APP.route(path, methods=methods, endpoint=endpoint)(measured_func)

    return decorator


def app_route_performance_measure(route_path: str, http_methods: list[str] | None = None) -> Callable:
    """Decorator that measures and logs route performance with path and method information."""

    # def format_time(seconds: float) -> str:
    #     """Format time in appropriate units (µs or ms)."""
    #     microseconds = seconds * 1_000_000
    #     if microseconds < 1000:
    #         return f"{microseconds:.2f} µs"
    #     else:
    #         milliseconds = microseconds / 1000
    #         return f"{milliseconds:.2f} ms"

    def decorator(f: Callable[P, Coroutine[Any, Any, T]]) -> Callable[P, Awaitable[T]]:
        @functools.wraps(f)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            # This wrapper is based on an outstanding idea by Mostafa Farzán
            # Farzán realised that we can step the event loop manually
            # That way, we can also divide it into synchronous and asynchronous parts
            # The synchronous part is done using coro.send(None)
            # The asynchronous part is done using asyncio.sleep(0)
            # We use two methods for measuring the async part, and take the largest
            # This performance measurement adds a bit of overhead, about 10-20ms
            # Therefore it should be avoided in production, or made more efficient
            # We could perhaps use for a small portion of requests
            blocking_time = 0.0
            async_time = 0.0
            loop_time = 0.0
            total_start = time.perf_counter()
            coro = f(*args, **kwargs)
            try:
                while True:
                    # Measure the synchronous part
                    sync_start = time.perf_counter()
                    future = coro.send(None)
                    sync_end = time.perf_counter()
                    blocking_time += sync_end - sync_start

                    # Measure the asynchronous part in two different ways
                    loop = asyncio.get_running_loop()
                    wait_start = time.perf_counter()
                    loop_start = loop.time()
                    while not future.done():
                        await asyncio.sleep(0)
                    wait_end = time.perf_counter()
                    loop_end = loop.time()
                    async_time += wait_end - wait_start
                    loop_time += loop_end - loop_start

                    # Raise exception if any
                    # future.result()
            except StopIteration as e:
                total_end = time.perf_counter()
                total_time = total_end - total_start

                methods_str = ",".join(http_methods) if http_methods else "GET"

                nonblocking_time = max(async_time, loop_time)
                # If async time is more than 10% different from loop time, log it
                delta_symbol = "="
                nonblocking_delta = abs(async_time - loop_time)
                # Must check that nonblocking_time is not 0 to avoid division by zero
                if nonblocking_time and ((nonblocking_delta / nonblocking_time) > 0.1):
                    delta_symbol = "!"
                route_logger.info(
                    "%s %s %s %s %s %s %s",
                    methods_str,
                    route_path,
                    f.__name__,
                    delta_symbol,
                    int(blocking_time * 1000),
                    int(nonblocking_time * 1000),
                    int(total_time * 1000),
                )

                return e.value

        return wrapper

    return decorator


def format_file_size(size_in_bytes: int) -> str:
    """Format a file size with appropriate units and comma-separated digits."""
    # Format the raw bytes with commas
    formatted_bytes = f"{size_in_bytes:,}"

    # Calculate the appropriate unit
    if size_in_bytes >= 1_000_000_000:
        size_in_gb = size_in_bytes // 1_000_000_000
        return f"{size_in_gb:,} GB ({formatted_bytes} bytes)"
    elif size_in_bytes >= 1_000_000:
        size_in_mb = size_in_bytes // 1_000_000
        return f"{size_in_mb:,} MB ({formatted_bytes} bytes)"
    elif size_in_bytes >= 1_000:
        size_in_kb = size_in_bytes // 1_000
        return f"{size_in_kb:,} KB ({formatted_bytes} bytes)"
    else:
        return f"{formatted_bytes} bytes"


async def get_form(request: quart.Request) -> datastructures.MultiDict:
    # The request.form() method in Quart calls a synchronous tempfile method
    # It calls quart.wrappers.request.form _load_form_data
    # Which calls quart.formparser parse and parse_func and parser.parse
    # Which calls _write which calls tempfile, which is synchronous
    # It's getting a tempfile back from some prior call
    # We can't just make blockbuster ignore the call because then it ignores it everywhere
    app = asfquart.APP

    if app is ...:
        raise RuntimeError("APP is not set")

    # Or quart.current_app?
    blockbuster = app.extensions.get("blockbuster")

    # Turn blockbuster off
    if blockbuster is not None:
        blockbuster.deactivate()
    form = await request.form
    # Turn blockbuster on
    if blockbuster is not None:
        blockbuster.activate()
    return form


R = TypeVar("R", covariant=True)


# This is the type of functions to which we apply @committer_get
# In other words, functions which accept CommitterSession as their first arg
class CommitterRouteHandler(Protocol[R]):
    """Protocol for @committer_get decorated functions."""

    __name__: str
    __doc__: str | None

    def __call__(self, session: CommitterSession, *args: Any, **kwargs: Any) -> Awaitable[R]: ...


class CommitterSession:
    """Session with extra information about committers."""

    def __init__(self, web_session: session.ClientSession) -> None:
        self._projects: list[models.Project] | None = None
        self._session = web_session

    def __getattr__(self, name: str) -> Any:
        # TODO: Not type safe, should subclass properly if possible
        # For example, we can access session.no_such_attr and the type checkers won't notice
        return getattr(self._session, name)

    @property
    def host(self) -> str:
        request_host = quart.request.host
        if ":" in request_host:
            domain, port = request_host.split(":")
            # Could be an IPv6 address, so need to check whether port is a valid integer
            if port.isdigit():
                return domain
        return request_host

    @property
    async def user_candidate_drafts(self) -> list[models.Release]:
        return await user.candidate_drafts(self.uid, user_projects=self._projects)

    @property
    async def user_projects(self) -> list[models.Project]:
        if self._projects is None:
            self._projects = await user.projects(self.uid)
        return self._projects

    @property
    async def user_releases(self) -> list[models.Release]:
        return await user.releases(self.uid)


# This is the type of functions to which we apply @app_route
# In other words, functions which accept no session
class RouteHandler(Protocol[R]):
    """Protocol for @app_route decorated functions."""

    __name__: str
    __doc__: str | None

    def __call__(self, *args: Any, **kwargs: Any) -> Awaitable[R]: ...


# This decorator is an adaptor between @committer_get and @app_route functions
def committer_route(
    path: str, methods: list[str] | None = None
) -> Callable[[CommitterRouteHandler[R]], RouteHandler[R]]:
    """Decorator for committer GET routes that provides an enhanced session object."""

    def decorator(func: CommitterRouteHandler[R]) -> RouteHandler[R]:
        async def wrapper(*args: Any, **kwargs: Any) -> R:
            web_session = await session.read()
            if web_session is None:
                _authentication_failed()

            enhanced_session = CommitterSession(web_session)
            return await func(enhanced_session, *args, **kwargs)

        # Generate a unique endpoint name
        endpoint = func.__module__ + "_" + func.__name__

        # Set the name before applying decorators
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        wrapper.__annotations__["endpoint"] = endpoint

        # Apply decorators in reverse order
        decorated = auth.require(auth.Requirements.committer)(wrapper)
        decorated = app_route(path, methods=methods or ["GET"], endpoint=endpoint)(decorated)

        return decorated

    return decorator


def _authentication_failed() -> NoReturn:
    """Handle authentication failure with an exception."""
    # NOTE: This is a separate function to fix a problem with analysis flow in mypy
    raise base.ASFQuartException("Not authenticated", errorcode=401)
