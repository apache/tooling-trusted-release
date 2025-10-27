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

import time
from collections.abc import Awaitable, Callable
from types import ModuleType
from typing import Any

import asfquart.auth as auth
import asfquart.base as base
import asfquart.session
import quart

import atr.log as log
import atr.web as web

_BLUEPRINT_NAME = "get_blueprint"
_BLUEPRINT = quart.Blueprint(_BLUEPRINT_NAME, __name__)


def register(app: base.QuartApp) -> ModuleType:
    import atr.get as get

    app.register_blueprint(_BLUEPRINT)
    return get


def committer(path: str) -> Callable[[web.CommitterRouteFunction[Any]], web.RouteFunction[Any]]:
    def decorator(func: web.CommitterRouteFunction[Any]) -> web.RouteFunction[Any]:
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            web_session = await asfquart.session.read()
            if web_session is None:
                raise base.ASFQuartException("Not authenticated", errorcode=401)

            enhanced_session = web.Committer(web_session)
            start_time_ns = time.perf_counter_ns()
            response = await func(enhanced_session, *args, **kwargs)
            end_time_ns = time.perf_counter_ns()
            total_ns = end_time_ns - start_time_ns
            total_ms = total_ns // 1_000_000

            # TODO: Make this configurable in config.py
            log.performance(
                "%s %s %s %s %s %s %s",
                "GET",
                path,
                func.__name__,
                "=",
                0,
                0,
                total_ms,
            )

            return response

        endpoint = func.__module__.replace(".", "_") + "_" + func.__name__
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        wrapper.__annotations__["endpoint"] = _BLUEPRINT_NAME + "." + endpoint

        decorated = auth.require(auth.Requirements.committer)(wrapper)
        _BLUEPRINT.add_url_rule(path, endpoint=endpoint, view_func=decorated, methods=["GET"])

        return decorated

    return decorator


def public(path: str) -> Callable[[Callable[..., Awaitable[Any]]], web.RouteFunction[Any]]:
    def decorator(func: Callable[..., Awaitable[Any]]) -> web.RouteFunction[Any]:
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            web_session = await asfquart.session.read()
            enhanced_session = web.Committer(web_session) if web_session else None
            return await func(enhanced_session, *args, **kwargs)

        endpoint = func.__module__.replace(".", "_") + "_" + func.__name__
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        wrapper.__annotations__["endpoint"] = _BLUEPRINT_NAME + "." + endpoint

        _BLUEPRINT.add_url_rule(path, endpoint=endpoint, view_func=wrapper, methods=["GET"])

        return wrapper

    return decorator
