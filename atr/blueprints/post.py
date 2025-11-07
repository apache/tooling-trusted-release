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

import json
import time
from collections.abc import Awaitable, Callable
from types import ModuleType
from typing import Any

import asfquart.auth as auth
import asfquart.base as base
import asfquart.session
import markupsafe
import pydantic
import quart

import atr.form
import atr.htm as htm
import atr.log as log
import atr.web as web

_BLUEPRINT_NAME = "post_blueprint"
_BLUEPRINT = quart.Blueprint(_BLUEPRINT_NAME, __name__)
_routes: list[str] = []


def register(app: base.QuartApp) -> tuple[ModuleType, list[str]]:
    import atr.post as post

    app.register_blueprint(_BLUEPRINT)
    return post, _routes


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
                "POST",
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
        _BLUEPRINT.add_url_rule(path, endpoint=endpoint, view_func=decorated, methods=["POST"])

        module_name = func.__module__.split(".")[-1]
        _routes.append(f"post.{module_name}.{func.__name__}")

        return decorated

    return decorator


def empty() -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    # This means that instead of:
    #
    # @post.form(form.Empty)
    # async def test_empty(
    #     session: web.Committer | None,
    #     form: form.Empty,
    # ) -> web.WerkzeugResponse:
    #     pass
    #
    # We can use:
    #
    # @post.empty()
    # async def test_empty(
    #     session: web.Committer | None,
    # ) -> web.WerkzeugResponse:
    #     pass
    def decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        async def wrapper(session: web.Committer | None, *args: Any, **kwargs: Any) -> Any:
            try:
                form_data = await atr.form.quart_request()
                context = {"session": session}
                atr.form.validate(atr.form.Empty, form_data, context)
                return await func(session, *args, **kwargs)
            except pydantic.ValidationError:
                # This presumably should not happen, because the CSRF token checker reaches it first
                msg = "Sorry, your form session expired for security reasons. Please try again."
                await quart.flash(msg, "error")
                return quart.redirect(quart.request.path)

        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        wrapper.__annotations__ = func.__annotations__.copy()
        return wrapper

    return decorator


def form(
    form_cls: Any,
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    def decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        async def wrapper(session: web.Committer | None, *args: Any, **kwargs: Any) -> Any:
            form_data = await atr.form.quart_request()
            try:
                context = {"session": session}
                validated_form = atr.form.validate(form_cls, form_data, context)
                return await func(session, validated_form, *args, **kwargs)
            except pydantic.ValidationError as e:
                errors = e.errors()
                if len(errors) == 0:
                    raise RuntimeError("Validation failed, but no errors were reported")
                flash_data = atr.form.flash_error_data(form_cls, errors, form_data)

                plural = len(errors) > 1
                summary = f"Please fix the following issue{'s' if plural else ''}:"
                ul = htm.Block(htm.ul, classes=".mt-2.mb-0")
                for i, flash_datum in enumerate(flash_data.values()):
                    if i > 9:
                        ul.li["And more, not shown here..."]
                        break
                    if "msg" in flash_datum:
                        ul.li[htm.strong[flash_datum["label"]], ": ", flash_datum["msg"]]
                summary = f"{summary}\n{ul.collect()}"

                # TODO: Centralise all uses of markupsafe.Markup
                # log.info(f"Flash data: {flash_data}")
                await quart.flash(markupsafe.Markup(summary), category="error")
                await quart.flash(json.dumps(flash_data), category="form-error-data")
                return quart.redirect(quart.request.path)

        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        wrapper.__annotations__ = func.__annotations__.copy()
        return wrapper

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

        _BLUEPRINT.add_url_rule(path, endpoint=endpoint, view_func=wrapper, methods=["POST"])

        module_name = func.__module__.split(".")[-1]
        _routes.append(f"post.{module_name}.{func.__name__}")

        return wrapper

    return decorator
