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


@dataclasses.dataclass
class Pagination:
    offset: int = 0
    limit: int = 20


@dataclasses.dataclass
class Task(Pagination):
    status: str | None = None


# We implicitly have /api/openapi.json


@api.BLUEPRINT.route("/committees")
@quart_schema.validate_response(list[models.Committee], 200)
async def committees() -> tuple[list[Mapping], int]:
    """List all committees in the database."""
    async with db.session() as data:
        committees = await data.committee().all()
        return [committee.model_dump() for committee in committees], 200


@api.BLUEPRINT.route("/projects")
@quart_schema.validate_response(list[models.Committee], 200)
async def projects() -> tuple[list[Mapping], int]:
    """List all projects in the database."""
    async with db.session() as data:
        committees = await data.committee().all()
        return [committee.model_dump() for committee in committees], 200


@api.BLUEPRINT.route("/projects/<name>")
@quart_schema.validate_response(models.Committee, 200)
async def projects_name(name: str) -> tuple[Mapping, int]:
    async with db.session() as data:
        committee = await data.committee(name=name).demand(exceptions.NotFound())
        return committee.model_dump(), 200


@api.BLUEPRINT.route("/projects/<name>/releases")
@quart_schema.validate_response(list[models.Release], 200)
async def projects_name_releases(name: str) -> tuple[list[Mapping], int]:
    async with db.session() as data:
        releases = await data.release(project_name=name).all()
        return [release.model_dump() for release in releases], 200


@api.BLUEPRINT.route("/tasks")
@quart_schema.validate_querystring(Task)
async def tasks(query_args: Task) -> quart.Response:
    _pagination_args_validate(query_args)
    via = models.validate_instrumented_attribute
    async with db.session() as data:
        statement = sqlmodel.select(models.Task).limit(query_args.limit).offset(query_args.offset)
        if query_args.status:
            if query_args.status not in models.TaskStatus:
                raise exceptions.BadRequest(f"Invalid status: {query_args.status}")
            statement = statement.where(models.Task.status == query_args.status)
        statement = statement.order_by(via(models.Task.id).desc())
        paged_tasks = (await data.execute(statement)).scalars().all()
        count_statement = sqlalchemy.select(sqlalchemy.func.count(via(models.Task.id)))
        if query_args.status:
            count_statement = count_statement.where(via(models.Task.status) == query_args.status)
        count = (await data.execute(count_statement)).scalar_one()
        result = {"data": [paged_task.model_dump(exclude={"result"}) for paged_task in paged_tasks], "count": count}
        return quart.jsonify(result)


def _pagination_args_validate(query_args: Pagination) -> None:
    # Users could request any amount using limit=N with arbitrarily high N
    # We therefore limit the maximum limit to 1000
    if query_args.limit > 1000:
        # quart.abort(400, "Limit is too high")
        raise exceptions.BadRequest("Maximum limit of 1000 exceeded")
