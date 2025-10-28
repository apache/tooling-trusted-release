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
import pathlib
from types import ModuleType
from typing import Protocol, runtime_checkable

import asfquart.base as base

import atr.blueprints.admin as admin
import atr.blueprints.api as api
import atr.blueprints.get as get
import atr.blueprints.icons as icons
import atr.blueprints.post as post

_all_routes: list[str] = []


@runtime_checkable
class RoutesModule(Protocol):
    ROUTES_MODULE: bool = True


def register(app: base.QuartApp) -> None:
    import atr.config as config

    _check_blueprint(*admin.register(app))
    _check_blueprint(*api.register(app))
    _check_blueprint(*get.register(app))
    app.register_blueprint(icons.BLUEPRINT)
    _check_blueprint(*post.register(app))

    _export_routes(pathlib.Path(config.get().STATE_DIR))


def _check_blueprint(module: ModuleType, routes: list[str]) -> None:
    # We need to know that the routes were actually imported
    # Otherwise ASFQuart will not know about them, even if the blueprint is registered
    # In other words, registering a blueprint does not automatically import its routes
    if not isinstance(module, RoutesModule):
        raise ValueError(f"Module {module} is not a RoutesModule")
    _all_routes.extend(routes)


def _export_routes(state_dir: pathlib.Path) -> None:
    routes_file = state_dir / "routes.json"
    routes_file.write_text(json.dumps(sorted(_all_routes), indent=2))
