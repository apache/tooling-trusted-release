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

import asyncio
import contextlib
import datetime
import os
import queue
from collections.abc import Iterable
from types import ModuleType
from typing import Any

import asfquart
import asfquart.base as base
import asfquart.generics
import asfquart.session
import blockbuster
import quart
import quart_schema
import quart_wtf
import rich.logging as rich_logging
import werkzeug.routing as routing

import atr
import atr.blueprints as blueprints
import atr.bps as bps
import atr.config as config
import atr.db as db
import atr.db.interaction as interaction
import atr.filters as filters
import atr.log as log
import atr.manager as manager
import atr.models.sql as sql
import atr.preload as preload
import atr.ssh as ssh
import atr.svn.pubsub as pubsub
import atr.tasks as tasks
import atr.template as template
import atr.user as user
import atr.util as util

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


def app_create_base(app_config: type[config.AppConfig]) -> base.QuartApp:
    """Create the base Quart application."""
    if asfquart.construct is ...:
        raise ValueError("asfquart.construct is not set")
    app = asfquart.construct(__name__)
    app.config.from_object(app_config)
    return app


def app_dirs_setup(app_config: type[config.AppConfig]) -> None:
    """Setup application directories."""
    if not os.path.isdir(app_config.STATE_DIR):
        raise RuntimeError(f"State directory not found: {app_config.STATE_DIR}")
    os.chdir(app_config.STATE_DIR)
    print(f"Working directory changed to: {os.getcwd()}")

    directories_to_ensure = [
        util.get_downloads_dir(),
        util.get_finished_dir(),
        util.get_tmp_dir(),
        util.get_unfinished_dir(),
    ]
    for directory in directories_to_ensure:
        directory.mkdir(parents=True, exist_ok=True)
        util.chmod_directories(directory, permissions=0o755)


def app_setup_api_docs(app: base.QuartApp) -> None:
    """Configure OpenAPI documentation."""
    import quart_schema

    import atr.metadata as metadata

    quart_schema.QuartSchema(
        app,
        info=quart_schema.Info(
            title="ATR API",
            description="OpenAPI documentation for the Apache Trusted Releases (ATR) platform.",
            version=metadata.version,
        ),
        openapi_provider_class=ApiOnlyOpenAPIProvider,
        swagger_ui_path="/api/docs",
        openapi_path="/api/openapi.json",
        security_schemes={
            "BearerAuth": quart_schema.HttpSecurityScheme(
                scheme="bearer",
                bearer_format="JWT",
            )
        },
    )


def app_setup_context(app: base.QuartApp) -> None:
    """Setup application context processor."""

    @app.context_processor
    async def app_wide() -> dict[str, Any]:
        import atr.admin as admin
        import atr.metadata as metadata
        import atr.routes as routes
        import atr.routes.mapping as mapping

        return {
            "admin": admin,
            "as_url": util.as_url,
            "commit": metadata.commit,
            "current_user": await asfquart.session.read(),
            "is_admin_fn": user.is_admin,
            "is_viewing_as_admin_fn": util.is_user_viewing_as_admin,
            "is_committee_member_fn": user.is_committee_member,
            "routes": routes,
            "unfinished_releases_fn": interaction.unfinished_releases,
            # "user_committees_fn": interaction.user_committees,
            "user_projects_fn": interaction.user_projects,
            "release_as_url": mapping.release_as_url,
            "version": metadata.version,
        }


def app_setup_lifecycle(app: base.QuartApp) -> None:
    """Setup application lifecycle hooks."""

    @app.before_serving
    async def startup() -> None:
        """Start services before the app starts serving requests."""
        if listener := app.extensions.get("logging_listener"):
            listener.start()

        worker_manager = manager.get_worker_manager()
        await worker_manager.start()

        # Start the metadata update scheduler
        metadata_scheduler_task = asyncio.create_task(_metadata_update_scheduler())
        app.extensions["metadata_scheduler"] = metadata_scheduler_task

        await initialise_test_environment()

        conf = config.get()
        pubsub_url = conf.PUBSUB_URL
        pubsub_user = conf.PUBSUB_USER
        pubsub_password = conf.PUBSUB_PASSWORD

        if pubsub_url and pubsub_user and pubsub_password:
            log.info("Starting PubSub SVN listener")
            listener = pubsub.SVNListener(
                working_copy_root=conf.SVN_STORAGE_DIR,
                url=pubsub_url,
                username=pubsub_user,
                password=pubsub_password,
            )
            task = asyncio.create_task(listener.start())
            app.extensions["svn_listener"] = task
            log.info("PubSub SVN listener task created")
        else:
            log.info(
                "PubSub SVN listener not started: pubsub_url=%s pubsub_user=%s pubsub_password=%s",
                bool(pubsub_url),
                bool(pubsub_user),
                # Essential to use bool(...) here to avoid logging the password
                bool(pubsub_password),
            )

        ssh_server = await ssh.server_start()
        app.extensions["ssh_server"] = ssh_server

    @app.after_serving
    async def shutdown() -> None:
        """Clean up services after the app stops serving requests."""
        worker_manager = manager.get_worker_manager()
        await worker_manager.stop()

        # Stop the metadata scheduler
        metadata_scheduler = app.extensions.get("metadata_scheduler")
        if metadata_scheduler:
            metadata_scheduler.cancel()
            try:
                await metadata_scheduler
            except asyncio.CancelledError:
                ...

        ssh_server = app.extensions.get("ssh_server")
        if ssh_server:
            await ssh.server_stop(ssh_server)

        if task := app.extensions.get("svn_listener"):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        if listener := app.extensions.get("logging_listener"):
            listener.stop()

        await db.shutdown_database()

        app.background_tasks.clear()


def app_setup_logging(app: base.QuartApp, config_mode: config.Mode, app_config: type[config.AppConfig]) -> None:
    """Setup application logging."""
    import logging
    import logging.handlers

    console_handler = rich_logging.RichHandler(rich_tracebacks=True, show_time=False)
    log_queue = queue.Queue(-1)
    listener = logging.handlers.QueueListener(log_queue, console_handler)
    app.extensions["logging_listener"] = listener

    logging.basicConfig(
        format="[ %(asctime)s.%(msecs)03d ] %(process)d <%(name)s> %(message)s",
        level=logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.handlers.QueueHandler(log_queue)],
        force=True,
    )

    # Configure dedicated audit logger
    try:
        audit_handler = logging.FileHandler(
            app_config.STORAGE_AUDIT_LOG_FILE,
            encoding="utf-8",
            mode="a",
        )
        # audit_handler.setFormatter(
        #     logging.Formatter("%(message)s")
        # )
        audit_queue = queue.Queue(-1)
        audit_listener = logging.handlers.QueueListener(audit_queue, audit_handler)
        audit_listener.start()
        app.extensions["audit_listener"] = audit_listener

        audit_logger = logging.getLogger("atr.storage.audit")
        audit_logger.setLevel(logging.INFO)
        audit_logger.addHandler(audit_handler)
        audit_logger.propagate = False
        audit_queue_handler = logging.handlers.QueueHandler(audit_queue)
        audit_logger.handlers = [audit_queue_handler]
    except Exception:
        logging.getLogger(__name__).exception("Failed to configure audit logger")

    # Enable debug output for atr.* in DEBUG mode
    if config_mode == config.Mode.Debug:
        logging.getLogger(atr.__name__).setLevel(logging.DEBUG)

    # Only log in the worker process
    @app.before_serving
    async def log_debug_info() -> None:
        if config_mode == config.Mode.Debug or config_mode == config.Mode.Profiling:
            log.info(f"DEBUG        = {config_mode == config.Mode.Debug}")
            log.info(f"ENVIRONMENT  = {config_mode.value}")
            log.info(f"STATE_DIR    = {app_config.STATE_DIR}")


def create_app(app_config: type[config.AppConfig]) -> base.QuartApp:
    """Create and configure the application."""
    config_mode = config.get_mode()
    app_dirs_setup(app_config)
    app = app_create_base(app_config)

    app_setup_api_docs(app)
    quart_wtf.CSRFProtect(app)
    db.init_database(app)
    register_routes(app)
    bps.register(app)
    blueprints.register(app)
    filters.register_filters(app)
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
            log.info("Blockbuster activated to detect blocking calls")

    @app.after_serving
    async def stop_blockbuster() -> None:
        bb = app.extensions.get("blockbuster")
        if bb is not None:
            bb.deactivate()
            log.info("Blockbuster deactivated")

    return app


async def _metadata_update_scheduler() -> None:
    """Periodically schedule remote metadata updates."""
    # Wait one minute to allow the server to start
    await asyncio.sleep(60)

    while True:
        try:
            task = await tasks.metadata_update(asf_uid="system")
            log.info(f"Scheduled remote metadata update with ID {task.id}")
        except Exception as e:
            log.exception(f"Failed to schedule remote metadata update: {e!s}")

        # Schedule next update in 24 hours
        await asyncio.sleep(86400)


async def initialise_test_environment() -> None:
    if not config.get().ALLOW_TESTS:
        return

    async with db.session() as data:
        test_committee = await data.committee(name="test").get()
        if not test_committee:
            test_committee = sql.Committee(
                name="test",
                full_name="Test Committee",
                is_podling=False,
                committee_members=["test"],
                committers=["test"],
                release_managers=["test"],
            )
            data.add(test_committee)
            await data.commit()

        test_project = await data.project(name="test").get()
        if not test_project:
            test_project = sql.Project(
                name="test",
                full_name="Apache Test",
                status=sql.ProjectStatus.ACTIVE,
                committee_name="test",
                created=datetime.datetime.now(datetime.UTC),
                created_by="test",
            )
            data.add(test_project)
            await data.commit()


def main() -> None:
    """Quart debug server"""
    global app
    if app is None:
        app = create_app(config.get())
    app.run(port=8080, ssl_keyfile="key.pem", ssl_certfile="cert.pem")


def register_routes(app: base.QuartApp) -> ModuleType:
    # NOTE: These imports are for their side effects only
    import atr.routes as routes

    # Add a global error handler to show helpful error messages with tracebacks
    @app.errorhandler(Exception)
    async def handle_any_exception(error: Exception) -> Any:
        import traceback

        # If the request was made to the API, return JSON
        if quart.request.path.startswith("/api"):
            status_code = getattr(error, "code", 500) if isinstance(error, Exception) else 500
            return quart.jsonify({"error": str(error)}), status_code

        # Required to give to the error.html template
        tb = traceback.format_exc()
        log.exception("Unhandled exception")
        return await template.render("error.html", error=str(error), traceback=tb, status_code=500), 500

    @app.errorhandler(base.ASFQuartException)
    async def handle_asfquart_exception(error: base.ASFQuartException) -> Any:
        # TODO: Figure out why pyright doesn't know about this attribute
        if quart.request.path.startswith("/api"):
            errorcode = getattr(error, "errorcode", 500)
            return quart.jsonify({"error": str(error)}), errorcode
        if not hasattr(error, "errorcode"):
            errorcode = 500
        else:
            errorcode = getattr(error, "errorcode")
        return await template.render("error.html", error=str(error), status_code=errorcode), errorcode

    # Add a global error handler in case a page does not exist.
    @app.errorhandler(404)
    async def handle_not_found(error: Exception) -> Any:
        # Serve JSON for API endpoints, HTML otherwise
        if quart.request.path.startswith("/api"):
            return quart.jsonify({"error": "404 Not Found"}), 404
        return await template.render("notfound.html", error="404 Not Found", traceback="", status_code=404), 404

    return routes


# FIXME: when running in SSL mode, you will receive these exceptions upon termination at times:
#        ssl.SSLError: [SSL: APPLICATION_DATA_AFTER_CLOSE_NOTIFY] application data after close notify (_ssl.c:2706)
#        related ticket: https://github.com/pgjones/hypercorn/issues/261
#        in production, we actually do not need SSL mode as SSL termination is handled by the apache reverse proxy.
#        the tooling-agenda app runs without SSL on agenda-test in a similar setup and it works fine.

if __name__ == "__main__":
    main()
else:
    app = create_app(config.get())
