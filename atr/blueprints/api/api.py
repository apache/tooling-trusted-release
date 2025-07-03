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
import atr.jwtoken as jwtoken

# FIXME: we need to return the dumped model instead of the actual pydantic class
#        as otherwise pyright will complain about the return type
#        it would work though, see https://github.com/pgjones/quart-schema/issues/91
#        For now, just explicitly dump the model.


@dataclasses.dataclass
class Pagination:
    offset: int = 0
    limit: int = 20


@dataclasses.dataclass
class Releases(Pagination):
    phase: str | None = None


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


@api.BLUEPRINT.route("/committees/<name>")
@quart_schema.validate_response(models.Committee, 200)
async def committees_name(name: str) -> tuple[Mapping, int]:
    """Get a specific committee by name."""
    async with db.session() as data:
        committee = await data.committee(name=name).demand(exceptions.NotFound())
        return committee.model_dump(), 200


@api.BLUEPRINT.route("/committees/<name>/keys")
@quart_schema.validate_response(list[models.PublicSigningKey], 200)
async def committees_name_keys(name: str) -> tuple[list[Mapping], int]:
    """List all public signing keys associated with a specific committee."""
    async with db.session() as data:
        committee = await data.committee(name=name, _public_signing_keys=True).demand(exceptions.NotFound())
        return [key.model_dump() for key in committee.public_signing_keys], 200


@api.BLUEPRINT.route("/committees/<name>/projects")
@quart_schema.validate_response(list[models.Project], 200)
async def committees_name_projects(name: str) -> tuple[list[Mapping], int]:
    """List all projects for a specific committee."""
    async with db.session() as data:
        committee = await data.committee(name=name, _projects=True).demand(exceptions.NotFound())
        return [project.model_dump() for project in committee.projects], 200


@api.BLUEPRINT.route("/keys")
@quart_schema.validate_querystring(Pagination)
async def public_keys(query_args: Pagination) -> quart.Response:
    """List all public signing keys with pagination support."""
    _pagination_args_validate(query_args)
    via = models.validate_instrumented_attribute
    async with db.session() as data:
        statement = (
            sqlmodel.select(models.PublicSigningKey)
            .limit(query_args.limit)
            .offset(query_args.offset)
            .order_by(via(models.PublicSigningKey.fingerprint).asc())
        )
        paged_keys = (await data.execute(statement)).scalars().all()
        count = (
            await data.execute(sqlalchemy.select(sqlalchemy.func.count(via(models.PublicSigningKey.fingerprint))))
        ).scalar_one()
        result = {"data": [key.model_dump() for key in paged_keys], "count": count}
        return quart.jsonify(result)


@api.BLUEPRINT.route("/keys/<fingerprint>")
@quart_schema.validate_response(models.PublicSigningKey, 200)
async def public_keys_fingerprint(fingerprint: str) -> tuple[Mapping, int]:
    """Return a single public signing key by fingerprint."""
    async with db.session() as data:
        key = await data.public_signing_key(fingerprint=fingerprint.lower()).demand(exceptions.NotFound())
        return key.model_dump(), 200


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
    """List all releases for a specific project."""
    async with db.session() as data:
        releases = await data.release(project_name=name).all()
        return [release.model_dump() for release in releases], 200


@api.BLUEPRINT.route("/releases")
@quart_schema.validate_querystring(Releases)
async def releases(query_args: Releases) -> quart.Response:
    """Paged list of releases with optional filtering by phase."""
    _pagination_args_validate(query_args)
    via = models.validate_instrumented_attribute
    async with db.session() as data:
        statement = sqlmodel.select(models.Release)

        if query_args.phase:
            try:
                phase_value = models.ReleasePhase(query_args.phase)
            except ValueError:
                raise exceptions.BadRequest(f"Invalid phase: {query_args.phase}")
            statement = statement.where(models.Release.phase == phase_value)

        statement = (
            statement.order_by(via(models.Release.created).desc()).limit(query_args.limit).offset(query_args.offset)
        )

        paged_releases = (await data.execute(statement)).scalars().all()

        count_stmt = sqlalchemy.select(sqlalchemy.func.count(via(models.Release.name)))
        if query_args.phase:
            phase_value = models.ReleasePhase(query_args.phase) if query_args.phase else None
            if phase_value is not None:
                count_stmt = count_stmt.where(via(models.Release.phase) == phase_value)

        count = (await data.execute(count_stmt)).scalar_one()

        result = {"data": [release.model_dump() for release in paged_releases], "count": count}
        return quart.jsonify(result)


@api.BLUEPRINT.route("/releases/<project>/<version>")
@quart_schema.validate_response(models.Release, 200)
async def releases_project_version(project: str, version: str) -> tuple[Mapping, int]:
    """Return a single release by project and version."""
    async with db.session() as data:
        release_name = models.release_name(project, version)
        release = await data.release(name=release_name).demand(exceptions.NotFound())
        return release.model_dump(), 200


@api.BLUEPRINT.route("/releases/<project>/<version>/check-results")
@quart_schema.validate_response(list[models.CheckResult], 200)
async def releases_project_version_check_results(project: str, version: str) -> tuple[list[Mapping], int]:
    """List all check results for a given release."""
    async with db.session() as data:
        release_name = models.release_name(project, version)
        check_results = await data.check_result(release_name=release_name).all()
        return [cr.model_dump() for cr in check_results], 200


@api.BLUEPRINT.route("/releases/<project>/<version>/revisions")
@quart_schema.validate_response(list[models.Revision], 200)
async def releases_project_version_revisions(project: str, version: str) -> tuple[list[Mapping], int]:
    """List all revisions for a given release."""
    async with db.session() as data:
        release_name = models.release_name(project, version)
        revisions = await data.revision(release_name=release_name).all()
        return [rev.model_dump() for rev in revisions], 200


@api.BLUEPRINT.route("/secret")
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_response(dict[str, str], 200)
async def secret() -> tuple[Mapping, int]:
    """Return a secret."""
    return {"secret": "*******"}, 200


@api.BLUEPRINT.route("/ssh-keys")
@quart_schema.validate_querystring(Pagination)
async def ssh_keys(query_args: Pagination) -> quart.Response:
    """Paged list of developer SSH public keys."""
    _pagination_args_validate(query_args)
    via = models.validate_instrumented_attribute
    async with db.session() as data:
        statement = (
            sqlmodel.select(models.SSHKey)
            .limit(query_args.limit)
            .offset(query_args.offset)
            .order_by(via(models.SSHKey.fingerprint).asc())
        )
        paged_keys = (await data.execute(statement)).scalars().all()

        count_stmt = sqlalchemy.select(sqlalchemy.func.count(via(models.SSHKey.fingerprint)))
        count = (await data.execute(count_stmt)).scalar_one()

        result = {"data": [key.model_dump() for key in paged_keys], "count": count}
        return quart.jsonify(result)


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
