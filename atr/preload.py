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

"""
Prevent blocking file operations from affecting the event loop.

This module prevents blocking file operations in Jinja2 template loading from
being run in an asynchronous context.
"""

import asyncio
import os
import pathlib

import asfquart.base as base


def setup_template_preloading(app: base.QuartApp) -> None:
    """Register the template preloading to happen before the async loop starts."""
    # Store the original before_serving functions
    original_before_serving = app.before_serving_funcs.copy()
    app.before_serving_funcs = []

    @app.before_serving
    async def preload_before_blockbuster() -> None:
        # Preload all templates
        # This doesn't really need to be asynchronous
        # We do this anyway to avoid being ironic
        await asyncio.to_thread(_preload_templates, app)

        # Run all the original before_serving functions
        for func in original_before_serving:
            await func()


def _preload_templates(app: base.QuartApp) -> None:
    """Preload all templates in the templates directory."""
    # We must disable automatic reload otherwise Jinja will check for modifications
    # Checking for modifications means that Jinja will call os.stat() in an asynchronous context
    app.jinja_env.auto_reload = False

    template_dir = pathlib.Path(os.path.join(os.path.dirname(os.getcwd()), "atr", "templates"))

    if not template_dir.exists():
        print(f"Warning: Template directory {template_dir} does not exist")
        return

    # Find all template files
    template_files: list[pathlib.Path] = []
    for extension in [".html", ".jinja", ".j2", ".txt"]:
        template_files.extend(template_dir.glob(f"**/*{extension}"))

    # For each template file, get its path relative to the template directory
    for template_file in template_files:
        try:
            relative_path = template_file.relative_to(template_dir)
            template_name = str(relative_path).replace("\\", "/")

            # Access the template to make Jinja load and cache it
            app.jinja_env.get_template(template_name)
        except Exception as e:
            print(f"Error preloading template {template_file}: {e}")
    print(f"Preloaded {len(template_files)} templates")
