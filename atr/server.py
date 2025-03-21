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

import asfquart
import asfquart.base as base
import asfquart.generics
import asfquart.session
import blockbuster
import quart
import quart_schema
import werkzeug.routing as routing

import atr.blueprints as blueprints
import atr.config as config
import atr.db as db
import atr.manager as manager
import atr.preload as preload
import atr.ssh as ssh

# TODO: Technically this is a global variable
# We should probably find a cleaner way to do this
app: base.QuartApp | None = None

# Avoid OIDC
asfquart.generics.OAUTH_URL_INIT = "https://oauth.apache.org/auth?state=%s&redirect_uri=%s"
asfquart.generics.OAUTH_URL_CALLBACK = "https://oauth.apache.org/token?code=%s"


class ApiOnlyOpenAPIProvider(quart_schema.OpenAPIProvider):
    def generate_rules(self) -> Iterable[routing.Rule]:
        for rule in super().generate_rules():
            if rule.rule.startswith("/api"):
                yield rule


def register_routes(app: base.QuartApp) -> tuple[str, ...]:
    # NOTE: These imports are for their side effects only
    import atr.routes.candidate as candidate
    import atr.routes.committees as committees
    import atr.routes.dev as dev
    import atr.routes.docs as docs
    import atr.routes.download as download
    import atr.routes.files as files
    import atr.routes.keys as keys
    import atr.routes.package as package
    import atr.routes.projects as projects
    import atr.routes.release as release
    import atr.routes.root as root
    import atr.routes.vote_policy as vote_policy

    # Add a global error handler to show helpful error messages with tracebacks.
    @app.errorhandler(Exception)
    async def handle_any_exception(error: Exception) -> Any:
        import traceback

        # Required to give to the error.html template
        tb = traceback.format_exc()
        app.logger.exception("Unhandled exception")
        return await quart.render_template("error.html", error=str(error), traceback=tb, status_code=500), 500

    @app.errorhandler(base.ASFQuartException)
    async def handle_asfquart_exception(error: base.ASFQuartException) -> Any:
        # TODO: Figure out why pyright doesn't know about this attribute
        if not hasattr(error, "errorcode"):
            errorcode = 500
        else:
            errorcode = getattr(error, "errorcode")
        return await quart.render_template("error.html", error=str(error), status_code=errorcode), errorcode

    # Add a global error handler in case a page does not exist.
    @app.errorhandler(404)
    async def handle_not_found(error: Exception) -> Any:
        return await quart.render_template("notfound.html", error="404 Not Found", traceback="", status_code=404), 404

    # Must do this otherwise ruff "fixes" this function by removing the imports
    return (
        candidate.__name__,
        committees.__name__,
        dev.__name__,
        docs.__name__,
        download.__name__,
        files.__name__,
        keys.__name__,
        package.__name__,
        projects.__name__,
        release.__name__,
        root.__name__,
        vote_policy.__name__,
    )


def app_dirs_setup(app_config: type[config.AppConfig]) -> None:
    """Setup application directories."""
    if not os.path.isdir(app_config.STATE_DIR):
        raise RuntimeError(f"State directory not found: {app_config.STATE_DIR}")
    os.chdir(app_config.STATE_DIR)
    print(f"Working directory changed to: {os.getcwd()}")
    os.makedirs(app_config.RELEASE_STORAGE_DIR, exist_ok=True)


def app_create_base(app_config: type[config.AppConfig]) -> base.QuartApp:
    """Create the base Quart application."""
    if asfquart.construct is ...:
        raise ValueError("asfquart.construct is not set")
    app = asfquart.construct(__name__)
    app.config.from_object(app_config)
    return app


def app_setup_api_docs(app: base.QuartApp) -> None:
    """Configure OpenAPI documentation."""
    import quart_schema

    import atr.metadata as metadata

    quart_schema.QuartSchema(
        app,
        info=quart_schema.Info(
            title="ATR API",
            description="OpenAPI documentation for the Apache Trusted Release Platform.",
            version=metadata.version,
        ),
        openapi_provider_class=ApiOnlyOpenAPIProvider,
        swagger_ui_path="/api/docs",
        openapi_path="/api/openapi.json",
    )


def app_setup_context(app: base.QuartApp) -> None:
    """Setup application context processor."""

    @app.context_processor
    async def app_wide() -> dict[str, Any]:
        from atr.metadata import commit, version
        from atr.util import is_admin

        return {
            "current_user": await asfquart.session.read(),
            "is_admin": is_admin,
            "commit": commit,
            "version": version,
        }


def app_setup_lifecycle(app: base.QuartApp) -> None:
    """Setup application lifecycle hooks."""

    @app.before_serving
    async def startup() -> None:
        """Start services before the app starts serving requests."""
        worker_manager = manager.get_worker_manager()
        await worker_manager.start()

        ssh_server = await ssh.server_start()
        app.extensions["ssh_server"] = ssh_server

    @app.after_serving
    async def shutdown() -> None:
        """Clean up services after the app stops serving requests."""
        worker_manager = manager.get_worker_manager()
        await worker_manager.stop()

        ssh_server = app.extensions.get("ssh_server")
        if ssh_server:
            await ssh.server_stop(ssh_server)

        app.background_tasks.clear()


def app_setup_logging(app: base.QuartApp, config_mode: config.Mode, app_config: type[config.AppConfig]) -> None:
    """Setup application logging."""
    logging.basicConfig(
        format="[%(asctime)s.%(msecs)03d  ] [%(process)d] [%(levelname)s] %(message)s",
        level=logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Only log in the worker process
    @app.before_serving
    async def log_debug_info() -> None:
        if config_mode == config.Mode.Debug or config_mode == config.Mode.Profiling:
            app.logger.info(f"DEBUG        = {config_mode == config.Mode.Debug}")
            app.logger.info(f"ENVIRONMENT  = {config_mode.value}")
            app.logger.info(f"STATE_DIR    = {app_config.STATE_DIR}")


def create_app(app_config: type[config.AppConfig]) -> base.QuartApp:
    """Create and configure the application."""
    app_dirs_setup(app_config)

    app = app_create_base(app_config)
    app_setup_api_docs(app)

    db.init_database(app)
    register_routes(app)
    blueprints.register(app)

    config_mode = config.get_mode()

    app_setup_context(app)
    app_setup_lifecycle(app)
    app_setup_logging(app, config_mode, app_config)

    # do not enable template pre-loading if we explicitly want to reload templates
    if not app_config.TEMPLATES_AUTO_RELOAD:
        preload.setup_template_preloading(app)

    @app.before_serving
    async def start_blockbuster() -> None:
        # "I'll have a P, please, Bob."
        bb: blockbuster.BlockBuster | None = None
        if config_mode == config.Mode.Profiling:
            bb = blockbuster.BlockBuster()
        app.extensions["blockbuster"] = bb
        if bb is not None:
            bb.activate()
            app.logger.info("Blockbuster activated to detect blocking calls")

    @app.after_serving
    async def stop_blockbuster() -> None:
        bb = app.extensions.get("blockbuster")
        if bb is not None:
            bb.deactivate()
            app.logger.info("Blockbuster deactivated")

    return app


def main() -> None:
    """Quart debug server"""
    global app
    if app is None:
        app = create_app(config.get())
    app.run(port=8080, ssl_keyfile="key.pem", ssl_certfile="cert.pem")


if __name__ == "__main__":
    main()
else:
    app = create_app(config.get())
