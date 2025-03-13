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
from dataclasses import dataclass

from quart import Response, jsonify
from quart_schema import validate_querystring, validate_response
from werkzeug.exceptions import NotFound

import atr.blueprints.api as api
from atr.db.models import PMC
from atr.db.service import get_pmc_by_name, get_pmcs, get_tasks

# FIXME: we need to return the dumped model instead of the actual pydantic class
#        as otherwise pyright will complain about the return type
#        it would work though, see https://github.com/pgjones/quart-schema/issues/91
#        For now, just explicitly dump the model.


@api.BLUEPRINT.route("/projects/<name>")
@validate_response(PMC, 200)
async def project_by_name(name: str) -> tuple[Mapping, int]:
    pmc = await get_pmc_by_name(name)
    if pmc:
        return pmc.model_dump(), 200
    else:
        raise NotFound()


@api.BLUEPRINT.route("/projects")
@validate_response(list[PMC], 200)
async def projects() -> tuple[list[Mapping], int]:
    """List all projects in the database."""
    pmcs = await get_pmcs()
    return [pmc.model_dump() for pmc in pmcs], 200


@dataclass
class Pagination:
    offset: int = 0
    limit: int = 20


@api.BLUEPRINT.route("/tasks")
@validate_querystring(Pagination)
async def api_tasks(query_args: Pagination) -> Response:
    paged_tasks, count = await get_tasks(limit=query_args.limit, offset=query_args.offset)
    result = {"data": [x.model_dump(exclude={"result"}) for x in paged_tasks], "count": count}
    return jsonify(result)
