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

import asyncio
from typing import Any

import jinja2
import quart
import quart.app as app
import quart.signals as signals


async def _render_in_thread(template: jinja2.Template, context: dict, app: app.Quart) -> str:
    if template.environment.is_async is False:
        raise RuntimeError("Template environment is not async")
    await signals.before_render_template.send_async(
        app,
        _sync_wrapper=app.ensure_async,  # type: ignore[arg-type]
        template=template,
        context=context,
    )
    rendered_template = await asyncio.to_thread(template.render, context)
    await signals.template_rendered.send_async(
        app,
        _sync_wrapper=app.ensure_async,  # type: ignore[arg-type]
        template=template,
        context=context,
    )
    return rendered_template


render_async = quart.render_template


async def render_sync(
    template_name_or_list: str | jinja2.Template | list[str | jinja2.Template],
    **context_vars: Any,
) -> str:
    app_instance = quart.current_app
    await app_instance.update_template_context(context_vars)
    template = app_instance.jinja_env.get_or_select_template(template_name_or_list)
    return await _render_in_thread(template, context_vars, app_instance)


render = render_sync
