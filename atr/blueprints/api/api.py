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

import dataclasses
from collections.abc import Mapping

import quart
import quart_schema
import sqlalchemy
import sqlalchemy.ext.asyncio
import sqlmodel
import werkzeug.exceptions as exceptions

import atr.blueprints.api as api
import atr.db as db
import atr.db.models as models

# FIXME: we need to return the dumped model instead of the actual pydantic class
#        as otherwise pyright will complain about the return type
#        it would work though, see https://github.com/pgjones/quart-schema/issues/91
#        For now, just explicitly dump the model.


@api.BLUEPRINT.route("/projects/<name>")
@quart_schema.validate_response(models.Committee, 200)
async def project_by_name(name: str) -> tuple[Mapping, int]:
    async with db.session() as data:
        committee = await data.committee(name=name).demand(exceptions.NotFound())
        return committee.model_dump(), 200


@api.BLUEPRINT.route("/projects")
@quart_schema.validate_response(list[models.Committee], 200)
async def projects() -> tuple[list[Mapping], int]:
    """List all projects in the database."""
    async with db.session() as data:
        committees = await data.committee().all()
        return [committee.model_dump() for committee in committees], 200


@dataclasses.dataclass
class Pagination:
    offset: int = 0
    limit: int = 20


@api.BLUEPRINT.route("/tasks")
@quart_schema.validate_querystring(Pagination)
async def api_tasks(query_args: Pagination) -> quart.Response:
    async with db.session() as data:
        statement = (
            sqlmodel.select(models.Task)
            .limit(query_args.limit)
            .offset(query_args.offset)
            .order_by(models.Task.id.desc())  # type: ignore
        )
        paged_tasks = (await data.execute(statement)).scalars().all()
        count = (await data.execute(sqlalchemy.select(sqlalchemy.func.count(models.Task.id)))).scalar_one()  # type: ignore
        result = {"data": [x.model_dump(exclude={"result"}) for x in paged_tasks], "count": count}
        return quart.jsonify(result)
