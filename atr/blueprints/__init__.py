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

from importlib import import_module
from importlib.util import find_spec

from asfquart.base import QuartApp

_BLUEPRINT_MODULES = ["secret"]


def register_blueprints(app: QuartApp) -> None:
    for routes_name in _BLUEPRINT_MODULES:
        routes_fqn = f"atr.blueprints.{routes_name}.{routes_name}"
        spec = find_spec(routes_fqn)
        if spec is not None:
            module = import_module(routes_fqn)
            app.register_blueprint(module.blueprint)
