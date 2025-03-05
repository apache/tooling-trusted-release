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
from typing import Any

from blockbuster import BlockBuster
from decouple import config
from quart_schema import OpenAPIProvider, QuartSchema
from werkzeug.routing import Rule

import asfquart
import asfquart.generics
import asfquart.session
from asfquart.base import QuartApp
from atr.blueprints import register_blueprints
from atr.config import AppConfig, ConfigMode, config_dict
from atr.db import create_database
from atr.manager import get_worker_manager
from atr.preload import setup_template_preloading

# WARNING: Don't run with debug turned on in production!
DEBUG = False
if config("PROFILING", default=False, cast=bool):
    config_mode = ConfigMode.Profiling
elif config("PRODUCTION", default=False, cast=bool):
    config_mode = ConfigMode.Production
else:
    config_mode = ConfigMode.Debug
    DEBUG = True


# Avoid OIDC
asfquart.generics.OAUTH_URL_INIT = "https://oauth.apache.org/auth?state=%s&redirect_uri=%s"
asfquart.generics.OAUTH_URL_CALLBACK = "https://oauth.apache.org/token?code=%s"

app: QuartApp | None = None


class ApiOnlyOpenAPIProvider(OpenAPIProvider):
    def generate_rules(self) -> Iterable[Rule]:
        for rule in super().generate_rules():
            if rule.rule.startswith("/api"):
                yield rule


def register_routes() -> tuple[str, ...]:
    from atr.routes import candidate, dev, docs, download, keys, package, project, release, root

    # Must do this otherwise ruff "fixes" this function by removing the imports
    return (
        candidate.__name__,
        dev.__name__,
        docs.__name__,
        download.__name__,
        keys.__name__,
        package.__name__,
        project.__name__,
        release.__name__,
        root.__name__,
    )


def create_config() -> type[AppConfig]:
    try:
        app_config = config_dict[config_mode]
    except KeyError:
        exit("Error: Invalid <config_mode>. Expected values [Debug, Production] ")

    return app_config


def app_dirs_setup(app_config: type[AppConfig]) -> None:
    """Setup application directories."""
    if not os.path.isdir(app_config.STATE_DIR):
        raise RuntimeError(f"State directory not found: {app_config.STATE_DIR}")
    os.chdir(app_config.STATE_DIR)
    print(f"Working directory changed to: {os.getcwd()}")
    os.makedirs(app_config.RELEASE_STORAGE_DIR, exist_ok=True)


def app_create_base(app_config: type[AppConfig]) -> QuartApp:
    """Create the base Quart application."""
    if asfquart.construct is ...:
        raise ValueError("asfquart.construct is not set")
    app = asfquart.construct(__name__)
    app.config.from_object(app_config)
    return app


def app_setup_api_docs(app: QuartApp) -> None:
    """Configure OpenAPI documentation."""
    from quart_schema import Info

    from atr.version import version

    QuartSchema(
        app,
        info=Info(
            title="ATR API",
            description="OpenAPI documentation for the Apache Trusted Release Platform.",
            version=version,
        ),
        openapi_provider_class=ApiOnlyOpenAPIProvider,
        swagger_ui_path="/api/docs",
        openapi_path="/api/openapi.json",
    )


def app_setup_context(app: QuartApp) -> None:
    """Setup application context processor."""

    @app.context_processor
    async def app_wide() -> dict[str, Any]:
        from atr.util import is_admin
        from atr.version import commit, version

        return {
            "current_user": await asfquart.session.read(),
            "is_admin": is_admin,
            "commit": commit,
            "version": version,
        }


def app_setup_lifecycle(app: QuartApp) -> None:
    """Setup application lifecycle hooks."""

    @app.before_serving
    async def startup() -> None:
        """Start services before the app starts serving requests."""
        worker_manager = get_worker_manager()
        await worker_manager.start()

    @app.after_serving
    async def shutdown() -> None:
        """Clean up services after the app stops serving requests."""
        worker_manager = get_worker_manager()
        await worker_manager.stop()
        app.background_tasks.clear()


def app_setup_logging(app: QuartApp, config_mode: str, app_config: type[AppConfig]) -> None:
    """Setup application logging."""
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


def create_app(app_config: type[AppConfig]) -> QuartApp:
    """Create and configure the application."""
    app_dirs_setup(app_config)

    app = app_create_base(app_config)
    app_setup_api_docs(app)

    create_database(app)
    register_routes()
    register_blueprints(app)

    app_setup_context(app)
    app_setup_lifecycle(app)
    app_setup_logging(app, config_mode.value, app_config)

    # do not enable template pre-loading if we explicitly want to reload templates
    if not app_config.TEMPLATES_AUTO_RELOAD:
        setup_template_preloading(app)

    @app.before_serving
    async def start_blockbuster() -> None:
        # "I'll have a P, please, Bob."
        blockbuster: BlockBuster | None = None
        if config_mode == ConfigMode.Profiling:
            blockbuster = BlockBuster()
        app.config["blockbuster"] = blockbuster
        if app.config["blockbuster"] is not None:
            app.config["blockbuster"].activate()
            app.logger.info("Blockbuster activated to detect blocking calls")

    @app.after_serving
    async def stop_blockbuster() -> None:
        if app.config["blockbuster"] is not None:
            app.config["blockbuster"].deactivate()
            app.logger.info("Blockbuster deactivated")

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
