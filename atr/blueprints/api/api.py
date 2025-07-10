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


import base64
import dataclasses
import datetime
import hashlib
import pathlib
from collections.abc import Mapping

import aiofiles.os
import asfquart.base as base
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
import atr.revision as revision
import atr.routes as routes
import atr.routes.draft as draft
import atr.routes.start as start
import atr.routes.voting as voting
import atr.schema as schema
import atr.tasks.vote as tasks_vote
import atr.user as user
import atr.util as util

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


class FileUploadRequest(schema.Strict):
    project_name: str
    version: str
    rel_path: str
    content: str


class PATJWTRequest(schema.Strict):
    asfuid: str
    pat: str


class ReleaseCreateRequest(schema.Strict):
    project_name: str
    version: str


class VoteStartRequest(schema.Strict):
    project_name: str
    version: str
    revision: str
    email_to: str
    vote_duration: int
    subject: str
    body: str


class DraftDeleteRequest(schema.Strict):
    project_name: str
    version: str


# We implicitly have /api/openapi.json


@api.BLUEPRINT.route("/checks/<project>/<version>")
@quart_schema.validate_response(list[models.CheckResult], 200)
async def checks_project_version(project: str, version: str) -> tuple[list[Mapping], int]:
    """List all check results for a given release."""
    async with db.session() as data:
        release_name = models.release_name(project, version)
        check_results = await data.check_result(release_name=release_name).all()
        return [cr.model_dump() for cr in check_results], 200


@api.BLUEPRINT.route("/checks/<project>/<version>/<revision>")
@quart_schema.validate_response(list[models.CheckResult], 200)
async def checks_project_version_revision(project: str, version: str, revision: str) -> tuple[list[Mapping], int]:
    """List all check results for a specific revision of a release."""
    async with db.session() as data:
        project_result = await data.project(name=project).get()
        if project_result is None:
            raise exceptions.NotFound(f"Project '{project}' does not exist")

        release_name = models.release_name(project, version)
        release_result = await data.release(name=release_name).get()
        if release_result is None:
            raise exceptions.NotFound(f"Release '{project}-{version}' does not exist")

        revision_result = await data.revision(release_name=release_name, number=revision).get()
        if revision_result is None:
            raise exceptions.NotFound(f"Revision '{revision}' does not exist for release '{project}-{version}'")

        check_results = await data.check_result(release_name=release_name, revision_number=revision).all()
        return [cr.model_dump() for cr in check_results], 200


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


@api.BLUEPRINT.route("/draft/delete", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_response(dict[str, str], 200)
async def draft_delete_project_version() -> tuple[dict[str, str], int]:
    payload = await _payload_get()
    req = DraftDeleteRequest.model_validate(payload)
    asf_uid = _jwt_asf_uid()

    async with db.session() as data:
        release_name = models.release_name(req.project_name, req.version)
        release = await data.release(
            name=release_name, phase=models.ReleasePhase.RELEASE_CANDIDATE_DRAFT, _committee=True
        ).demand(exceptions.NotFound())
        if not (user.is_committee_member(release.project.committee, asf_uid) or user.is_admin(asf_uid)):
            raise exceptions.Forbidden("You do not have permission to delete this draft")

        # TODO: This causes "A transaction is already begun on this Session"
        # async with data.begin():
        # Probably due to autobegin in data.release above
        await draft.delete_candidate_draft(data, release_name)
        await data.commit()
    return {"deleted": release_name}, 200


@api.BLUEPRINT.route("/list/<project>/<version>")
@api.BLUEPRINT.route("/list/<project>/<version>/<revision>")
@quart_schema.validate_response(dict[str, list[str]], 200)
async def list_project_version(
    project: str, version: str, revision: str | None = None
) -> tuple[dict[str, list[str]], int]:
    async with db.session() as data:
        release_name = models.release_name(project, version)
        release = await data.release(name=release_name).demand(exceptions.NotFound())
        if revision is None:
            dir_path = util.release_directory(release)
        else:
            await data.revision(release_name=release_name, number=revision).demand(exceptions.NotFound())
            dir_path = util.release_directory_version(release) / revision
    if not (await aiofiles.os.path.isdir(dir_path)):
        raise exceptions.NotFound("Files not found")
    files: list[str] = [str(path) for path in [p async for p in util.paths_recursive(dir_path)]]
    files.sort()
    return {"rel_paths": files}, 200


@api.BLUEPRINT.route("/jwt", methods=["POST"])
async def pat_jwt_post() -> quart.Response:
    """Generate a JWT from a valid PAT."""
    # Expects {"asfuid": "uid", "pat": "pat-token"}
    # Returns {"asfuid": "uid", "jwt": "jwt-token"}

    payload = await _payload_get()
    pat_request = PATJWTRequest.model_validate(payload)
    token_hash = hashlib.sha3_256(pat_request.pat.encode()).hexdigest()
    pat_rec = await _get_pat(pat_request.asfuid, token_hash)

    now = datetime.datetime.now(datetime.UTC)
    if (pat_rec is None) or (pat_rec.expires < now):
        return quart.Response("Invalid PAT", status=401)

    jwt_token = jwtoken.issue(pat_request.asfuid)
    return quart.jsonify({"asfuid": pat_request.asfuid, "jwt": jwt_token})


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


@api.BLUEPRINT.route("/releases/create", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_response(models.Release, 201)
async def releases_create() -> tuple[Mapping, int]:
    """Create a new release draft for a project via POSTed JSON."""

    payload = await _payload_get()
    request_data = ReleaseCreateRequest.model_validate(payload)
    asf_uid = _jwt_asf_uid()

    try:
        release, _project = await start.create_release_draft(
            project_name=request_data.project_name,
            version=request_data.version,
            asf_uid=asf_uid,
        )
    except routes.FlashError as exc:
        raise exceptions.BadRequest(str(exc))

    return release.model_dump(), 201


@api.BLUEPRINT.route("/releases/<project>")
@quart_schema.validate_querystring(Pagination)
async def releases_project(project: str, query_args: Pagination) -> quart.Response:
    """List all releases for a specific project with pagination."""
    _pagination_args_validate(query_args)
    async with db.session() as data:
        project_result = await data.project(name=project).get()
        if project_result is None:
            raise exceptions.NotFound(f"Project '{project}' does not exist")

        via = models.validate_instrumented_attribute
        statement = (
            sqlmodel.select(models.Release)
            .where(models.Release.project_name == project)
            .order_by(via(models.Release.created).desc())
            .limit(query_args.limit)
            .offset(query_args.offset)
        )

        paged_releases = (await data.execute(statement)).scalars().all()

        count_stmt = sqlalchemy.select(sqlalchemy.func.count(via(models.Release.name))).where(
            via(models.Release.project_name) == project
        )
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


# TODO: Rename this to revisions? I.e. /revisions/<project>/<version>
@api.BLUEPRINT.route("/releases/<project>/<version>/revisions")
@quart_schema.validate_response(list[models.Revision], 200)
async def releases_project_version_revisions(project: str, version: str) -> tuple[list[Mapping], int]:
    """List all revisions for a given release."""
    async with db.session() as data:
        release_name = models.release_name(project, version)
        revisions = await data.revision(release_name=release_name).all()
        return [rev.model_dump() for rev in revisions], 200


@api.BLUEPRINT.route("/revisions/<project>/<version>")
@quart_schema.validate_response(dict[str, list[models.Revision]], 200)
async def revisions_project_version(project: str, version: str) -> tuple[dict[str, list[models.Revision]], int]:
    async with db.session() as data:
        release_name = models.release_name(project, version)
        await data.release(name=release_name).demand(exceptions.NotFound())
        revisions = await data.revision(release_name=release_name).all()
    if not isinstance(revisions, list):
        revisions = list(revisions)
    revisions.sort(key=lambda rev: rev.number)
    return {"revisions": revisions}, 200


# @api.BLUEPRINT.route("/secret")
# @jwtoken.require
# @quart_schema.security_scheme([{"BearerAuth": []}])
# @quart_schema.validate_response(dict[str, str], 200)
# async def secret() -> tuple[Mapping, int]:
#     """Return a secret."""
#     return {"secret": "*******"}, 200


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


@api.BLUEPRINT.route("/vote/start", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_response(models.Task, 201)
async def vote_start() -> tuple[Mapping, int]:
    payload = await _payload_get()
    req = VoteStartRequest.model_validate(payload)
    asf_uid = _jwt_asf_uid()

    permitted_recipients = util.permitted_recipients(asf_uid)
    if req.email_to not in permitted_recipients:
        raise exceptions.Forbidden("Invalid mailing list choice")

    async with db.session() as data:
        release_name = models.release_name(req.project_name, req.version)
        release = await data.release(name=release_name, _project=True, _committee=True).demand(exceptions.NotFound())

        if not (user.is_committee_member(release.committee, asf_uid) or user.is_admin(asf_uid)):
            raise exceptions.Forbidden("You do not have permission to start a vote for this project")

        revision_exists = await data.revision(release_name=release_name, number=req.revision).get()
        if revision_exists is None:
            raise exceptions.NotFound(f"Revision '{req.revision}' does not exist")

        error = await voting.promote_release(data, release_name, req.revision, vote_manual=False)
        if error:
            raise exceptions.BadRequest(error)

        # TODO: Move this into a function in routes/voting.py
        task = models.Task(
            status=models.TaskStatus.QUEUED,
            task_type=models.TaskType.VOTE_INITIATE,
            task_args=tasks_vote.Initiate(
                release_name=release_name,
                email_to=req.email_to,
                vote_duration=req.vote_duration,
                initiator_id=asf_uid,
                initiator_fullname=asf_uid,
                subject=req.subject,
                body=req.body,
            ).model_dump(),
            project_name=req.project_name,
            version_name=req.version,
        )
        data.add(task)
        await data.commit()
        return task.model_dump(exclude={"result"}), 201


@api.BLUEPRINT.route("/upload", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_response(models.Revision, 201)
async def upload() -> tuple[Mapping, int]:
    payload = await _payload_get()
    req = FileUploadRequest.model_validate(payload)
    asf_uid = _jwt_asf_uid()

    async with db.session() as data:
        project = await data.project(name=req.project_name, _committee=True).demand(exceptions.NotFound())
        # TODO: user.is_participant(project, asf_uid)
        if not (user.is_committee_member(project.committee, asf_uid) or user.is_admin(asf_uid)):
            raise exceptions.Forbidden("You do not have permission to upload to this project")

    revision = await _upload_process_file(req, asf_uid)
    return revision.model_dump(), 201


@db.session_function
async def _get_pat(data: db.Session, uid: str, token_hash: str) -> models.PersonalAccessToken | None:
    return await data.query_one_or_none(
        sqlmodel.select(models.PersonalAccessToken).where(
            models.PersonalAccessToken.asfuid == uid,
            models.PersonalAccessToken.token_hash == token_hash,
        )
    )


def _jwt_asf_uid() -> str:
    claims = getattr(quart.g, "jwt_claims", {})
    asf_uid = claims.get("sub")
    if not isinstance(asf_uid, str):
        raise base.ASFQuartException("Invalid token subject", errorcode=401)
    return asf_uid


def _pagination_args_validate(query_args: Pagination) -> None:
    # Users could request any amount using limit=N with arbitrarily high N
    # We therefore limit the maximum limit to 1000
    if query_args.limit > 1000:
        # quart.abort(400, "Limit is too high")
        raise exceptions.BadRequest("Maximum limit of 1000 exceeded")


async def _payload_get() -> dict:
    payload = await quart.request.get_json(force=True, silent=False)
    if not isinstance(payload, dict):
        raise exceptions.BadRequest("Invalid JSON")
    return payload


async def _upload_process_file(req: FileUploadRequest, asf_uid: str) -> models.Revision:
    file_bytes = base64.b64decode(req.content, validate=True)
    file_path = req.rel_path.lstrip("/")
    description = f"Upload via API: {file_path}"
    async with revision.create_and_manage(req.project_name, req.version, asf_uid, description=description) as creating:
        target_path = pathlib.Path(creating.interim_path) / file_path
        await aiofiles.os.makedirs(target_path.parent, exist_ok=True)
        async with aiofiles.open(target_path, "wb") as f:
            await f.write(file_bytes)
    if creating.new is None:
        raise exceptions.InternalServerError("Failed to create revision")
    async with db.session() as data:
        release_name = models.release_name(req.project_name, req.version)
        return await data.revision(release_name=release_name, number=creating.new.number).demand(exceptions.NotFound())
