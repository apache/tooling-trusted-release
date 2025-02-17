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

from decouple import config

import asfquart
import asfquart.generics
import asfquart.session
from asfquart.base import QuartApp
from atr.blueprints import register_blueprints
from atr.config import AppConfig, config_dict
from atr.db import create_database

# Avoid OIDC
asfquart.generics.OAUTH_URL_INIT = "https://oauth.apache.org/auth?state=%s&redirect_uri=%s"
asfquart.generics.OAUTH_URL_CALLBACK = "https://oauth.apache.org/token?code=%s"


def register_routes() -> str:
    from . import routes

    # Must do this otherwise ruff "fixes" this function by removing the import.
    return routes.__name__


def create_app(app_config: type[AppConfig]) -> QuartApp:
    if asfquart.construct is ...:
        raise ValueError("asfquart.construct is not set")
    app = asfquart.construct(__name__)
    app.config.from_object(app_config)

    # # Configure static folder path before changing working directory
    # app.static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

    create_database(app)
    register_routes()
    register_blueprints(app)

    @app.context_processor
    async def app_wide():
        return {"current_user": await asfquart.session.read()}

    @app.after_serving
    async def shutdown() -> None:
        app.background_tasks.clear()

    return app


# WARNING: Don't run with debug turned on in production!
DEBUG: bool = config("DEBUG", default=True, cast=bool)

# Determine which configuration to use
config_mode = "Debug" if DEBUG else "Production"

try:
    app_config = config_dict[config_mode]
except KeyError:
    exit("Error: Invalid <config_mode>. Expected values [Debug, Production] ")

if not os.path.isdir(app_config.STATE_DIR):
    raise RuntimeError(f"State directory not found: {app_config.STATE_DIR}")
os.chdir(app_config.STATE_DIR)
print(f"Working directory changed to: {os.getcwd()}")

os.makedirs(app_config.RELEASE_STORAGE_DIR, exist_ok=True)

app = create_app(app_config)

logging.basicConfig(
    format="[%(asctime)s.%(msecs)03d  ] [%(process)d] [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)

if DEBUG:
    app.logger.info("DEBUG        = " + str(DEBUG))
    app.logger.info("ENVIRONMENT  = " + config_mode)
    app.logger.info("STATE_DIR    = " + app_config.STATE_DIR)


def main() -> None:
    """Quart debug server"""
    app.run(port=8080, ssl_keyfile="key.pem", ssl_certfile="cert.pem")


if __name__ == "__main__":
    main()
