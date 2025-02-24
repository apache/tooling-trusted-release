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

"""server.py"""

import logging
import os
from collections.abc import Iterable

from decouple import config
from quart_schema import OpenAPIProvider, QuartSchema
from werkzeug.routing import Rule

import asfquart
import asfquart.generics
import asfquart.session
from asfquart.base import QuartApp
from atr.blueprints import register_blueprints
from atr.config import AppConfig, config_dict
from atr.db import create_database
from atr.manager import get_worker_manager

# WARNING: Don't run with debug turned on in production!
DEBUG: bool = config("DEBUG", default=True, cast=bool)
# Determine which configuration to use
config_mode = "Debug" if DEBUG else "Production"

# Avoid OIDC
asfquart.generics.OAUTH_URL_INIT = "https://oauth.apache.org/auth?state=%s&redirect_uri=%s"
asfquart.generics.OAUTH_URL_CALLBACK = "https://oauth.apache.org/token?code=%s"

app: QuartApp | None = None


class ApiOnlyOpenAPIProvider(OpenAPIProvider):
    def generate_rules(self) -> Iterable[Rule]:
        for rule in super().generate_rules():
            if rule.rule.startswith("/api"):
                yield rule


def register_routes() -> str:
    from . import routes

    # Must do this otherwise ruff "fixes" this function by removing the import.
    return routes.__name__


def create_config() -> type[AppConfig]:
    try:
        app_config = config_dict[config_mode]
    except KeyError:
        exit("Error: Invalid <config_mode>. Expected values [Debug, Production] ")

    return app_config


def create_app(app_config: type[AppConfig]) -> QuartApp:
    if not os.path.isdir(app_config.STATE_DIR):
        raise RuntimeError(f"State directory not found: {app_config.STATE_DIR}")
    os.chdir(app_config.STATE_DIR)
    print(f"Working directory changed to: {os.getcwd()}")

    os.makedirs(app_config.RELEASE_STORAGE_DIR, exist_ok=True)

    if asfquart.construct is ...:
        raise ValueError("asfquart.construct is not set")
    app = asfquart.construct(__name__)
    app.config.from_object(app_config)

    # Add a from_json filter to the Jinja2 environment
    # app.jinja_env.filters["from_json"] = lambda x: json.loads(x) if x else None

    QuartSchema(
        app,
        openapi_provider_class=ApiOnlyOpenAPIProvider,
        swagger_ui_path="/api/docs",
        openapi_path="/api/openapi.json",
    )

    # # Configure static folder path before changing working directory
    # app.static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

    create_database(app)
    register_routes()
    register_blueprints(app)

    @app.context_processor
    async def app_wide():
        from atr.util import is_admin

        return {
            "current_user": await asfquart.session.read(),
            "is_admin": is_admin,
        }

    @app.before_serving
    async def startup() -> None:
        """Start services before the app starts serving requests."""
        # Start the worker manager
        worker_manager = get_worker_manager()
        await worker_manager.start()

    @app.after_serving
    async def shutdown() -> None:
        """Clean up services after the app stops serving requests."""
        # Stop the worker manager
        worker_manager = get_worker_manager()
        await worker_manager.stop()
        app.background_tasks.clear()

    # Configure logging
    logging.basicConfig(
        format="[%(asctime)s.%(msecs)03d  ] [%(process)d] [%(levelname)s] %(message)s",
        level=logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Only log in the worker process
    @app.before_serving
    async def log_debug_info() -> None:
        if DEBUG:
            app.logger.info("DEBUG        = " + str(DEBUG))
            app.logger.info("ENVIRONMENT  = " + config_mode)
            app.logger.info("STATE_DIR    = " + app_config.STATE_DIR)

    return app


def main() -> None:
    """Quart debug server"""
    global app
    if app is None:
        app = create_app(create_config())
    app.run(port=8080, ssl_keyfile="key.pem", ssl_certfile="cert.pem")


if __name__ == "__main__":
    main()
else:
    app = create_app(create_config())
