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

from collections.abc import Mapping
from typing import Any

from atr.db.service import get_pmc_by_name

from . import blueprint


@blueprint.route("/project/<project_name>")
async def api_pmc(project_name: str) -> tuple[Mapping[str, Any], int]:
    pmc = await get_pmc_by_name(project_name)
    if pmc:
        return pmc.model_dump(), 200
    else:
        return {}, 404
