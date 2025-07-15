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
import datetime
import hashlib
import pathlib
from collections.abc import Mapping
from typing import Any

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
import atr.db.interaction as interaction
import atr.jwtoken as jwtoken
import atr.models as models
import atr.models.sql as sql
import atr.revision as revision
import atr.routes as routes
import atr.routes.announce as announce
import atr.routes.keys as keys
import atr.routes.start as start
import atr.routes.voting as voting
import atr.tasks.vote as tasks_vote
import atr.user as user
import atr.util as util

# FIXME: we need to return the dumped model instead of the actual pydantic class
#        as otherwise pyright will complain about the return type
#        it would work though, see https://github.com/pgjones/quart-schema/issues/91
#        For now, just explicitly dump the model.

# We implicitly have /api/openapi.json

DictResponse = tuple[dict[str, Any], int]


@api.BLUEPRINT.route("/announce", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.AnnounceArgs)
@quart_schema.validate_response(models.api.AnnounceResults, 201)
async def announce_post(data: models.api.AnnounceArgs) -> DictResponse:
    asf_uid = _jwt_asf_uid()

    try:
        await announce.announce(
            data.project,
            data.version,
            data.revision,
            data.email_to,
            data.subject,
            data.body,
            data.path_suffix,
            asf_uid,
            asf_uid,
        )
    except announce.AnnounceError as e:
        raise exceptions.BadRequest(str(e))

    return models.api.AnnounceResults(
        endpoint="/announce",
        success="Announcement sent",
    ).model_dump(), 201


@api.BLUEPRINT.route("/checks/list/<project>/<version>")
@quart_schema.validate_response(models.api.ChecksListResults, 200)
async def checks_list_project_version(project: str, version: str) -> DictResponse:
    """List all check results for a given release."""
    _simple_check(project, version)
    # TODO: Merge with checks_list_project_version_revision
    async with db.session() as data:
        release_name = sql.release_name(project, version)
        check_results = await data.check_result(release_name=release_name).all()
        return models.api.ChecksListResults(
            endpoint="/checks/list",
            checks=check_results,
        ).model_dump(), 200


@api.BLUEPRINT.route("/checks/list/<project>/<version>/<revision>")
@quart_schema.validate_response(models.api.ChecksListResults, 200)
async def checks_list_project_version_revision(project: str, version: str, revision: str) -> DictResponse:
    """List all check results for a specific revision of a release."""
    _simple_check(project, version, revision)
    async with db.session() as data:
        project_result = await data.project(name=project).get()
        if project_result is None:
            raise exceptions.NotFound(f"Project '{project}' does not exist")

        release_name = sql.release_name(project, version)
        release_result = await data.release(name=release_name).get()
        if release_result is None:
            raise exceptions.NotFound(f"Release '{project}-{version}' does not exist")

        revision_result = await data.revision(release_name=release_name, number=revision).get()
        if revision_result is None:
            raise exceptions.NotFound(f"Revision '{revision}' does not exist for release '{project}-{version}'")

        check_results = await data.check_result(release_name=release_name, revision_number=revision).all()
        return models.api.ChecksListResults(
            endpoint="/checks/list",
            checks=check_results,
        ).model_dump(), 200


@api.BLUEPRINT.route("/checks/ongoing/<project>/<version>")
@api.BLUEPRINT.route("/checks/ongoing/<project>/<version>/<revision>")
@quart_schema.validate_response(models.api.ChecksOngoingResults, 200)
async def checks_ongoing_project_version(
    project: str,
    version: str,
    revision: str | None = None,
) -> DictResponse:
    """Return a count of all unfinished check results for a given release."""
    _simple_check(project, version, revision)
    ongoing_tasks_count, _latest_revision = await interaction.tasks_ongoing_revision(project, version, revision)
    # TODO: Is there a way to return just an int?
    # The ResponseReturnValue type in quart does not allow int
    # And if we use quart.jsonify, we must return quart.Response which quart_schema tries to validate
    # ResponseValue = Union[
    #     "Response",
    #     "WerkzeugResponse",
    #     bytes,
    #     str,
    #     Mapping[str, Any],  # any jsonify-able dict
    #     list[Any],  # any jsonify-able list
    #     Iterator[bytes],
    #     Iterator[str],
    # ]
    return models.api.ChecksOngoingResults(
        endpoint="/checks/ongoing",
        ongoing=ongoing_tasks_count,
    ).model_dump(), 200


# TODO: Rename all paths to avoid clashes
@api.BLUEPRINT.route("/committees/<name>")
@quart_schema.validate_response(models.api.CommitteesResults, 200)
async def committees_name(name: str) -> DictResponse:
    """Get a specific committee by name."""
    _simple_check(name)
    async with db.session() as data:
        committee = await data.committee(name=name).demand(exceptions.NotFound())
        return models.api.CommitteesResults(
            endpoint="/committees",
            committee=committee,
        ).model_dump(), 200


@api.BLUEPRINT.route("/committees/keys/<name>")
@quart_schema.validate_response(models.api.CommitteesKeysResults, 200)
async def committees_keys(name: str) -> DictResponse:
    """List all public signing keys associated with a specific committee."""
    _simple_check(name)
    async with db.session() as data:
        committee = await data.committee(name=name, _public_signing_keys=True).demand(exceptions.NotFound())
        return models.api.CommitteesKeysResults(
            endpoint="/committees/keys",
            keys=committee.public_signing_keys,
        ).model_dump(), 200


@api.BLUEPRINT.route("/committees/list")
@quart_schema.validate_response(models.api.CommitteesListResults, 200)
async def committees_list() -> DictResponse:
    """List all committees in the database."""
    async with db.session() as data:
        committees = await data.committee().all()
        return models.api.CommitteesListResults(
            endpoint="/committees/list",
            committees=committees,
        ).model_dump(), 200


@api.BLUEPRINT.route("/committees/projects/<name>")
@quart_schema.validate_response(models.api.CommitteesProjectsResults, 200)
async def committees_projects(name: str) -> DictResponse:
    """List all projects for a specific committee."""
    _simple_check(name)
    async with db.session() as data:
        committee = await data.committee(name=name, _projects=True).demand(exceptions.NotFound())
        return models.api.CommitteesProjectsResults(
            endpoint="/committees/projects",
            projects=committee.projects,
        ).model_dump(), 200


@api.BLUEPRINT.route("/draft/delete", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.DraftDeleteArgs)
@quart_schema.validate_response(models.api.DraftDeleteResults, 200)
async def draft_delete(data: models.api.DraftDeleteArgs) -> DictResponse:
    asf_uid = _jwt_asf_uid()

    async with db.session() as db_data:
        release_name = sql.release_name(data.project, data.version)
        release = await db_data.release(
            name=release_name, phase=sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT, _committee=True
        ).demand(exceptions.NotFound())
        if release.project.committee is None:
            raise exceptions.NotFound("Project has no committee")
        _committee_member_or_admin(release.project.committee, asf_uid)

        # TODO: This causes "A transaction is already begun on this Session"
        # async with data.begin():
        # Probably due to autobegin in data.release above
        # We pass the phase again to guard against races
        # But the removal is not actually locked
        await interaction.release_delete(
            release_name, phase=sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT, include_downloads=False
        )
        await db_data.commit()
    return models.api.DraftDeleteResults(
        endpoint="/draft/delete",
        success=f"Draft {release_name} deleted",
    ).model_dump(), 200


@api.BLUEPRINT.route("/jwt", methods=["POST"])
@quart_schema.validate_request(models.api.JwtArgs)
async def jwt_post(data: models.api.JwtArgs) -> DictResponse:
    """Generate a JWT from a valid PAT."""
    # Expects {"asfuid": "uid", "pat": "pat-token"}
    # Returns {"asfuid": "uid", "jwt": "jwt-token"}
    token_hash = hashlib.sha3_256(data.pat.encode()).hexdigest()
    pat_rec = await _get_pat(data.asfuid, token_hash)

    now = datetime.datetime.now(datetime.UTC)
    if (pat_rec is None) or (pat_rec.expires < now):
        raise exceptions.Unauthorized("Invalid PAT")

    jwt_token = jwtoken.issue(data.asfuid)
    return models.api.JwtResults(
        endpoint="/jwt",
        asfuid=data.asfuid,
        jwt=jwt_token,
    ).model_dump(), 200


@api.BLUEPRINT.route("/key/<fingerprint>")
@quart_schema.validate_response(models.api.KeyResults, 200)
async def key(fingerprint: str) -> DictResponse:
    """Return a single public signing key by fingerprint."""
    _simple_check(fingerprint)
    async with db.session() as data:
        key = await data.public_signing_key(fingerprint=fingerprint.lower()).demand(exceptions.NotFound())
        return models.api.KeyResults(
            endpoint="/key",
            key=key,
        ).model_dump(), 200


@api.BLUEPRINT.route("/keys")
@quart_schema.validate_querystring(models.api.KeysQuery)
@quart_schema.validate_response(models.api.KeysResults, 200)
async def public_keys(query_args: models.api.KeysQuery) -> DictResponse:
    """List all public signing keys with pagination support."""
    _pagination_args_validate(query_args)
    via = sql.validate_instrumented_attribute
    async with db.session() as data:
        statement = (
            sqlmodel.select(sql.PublicSigningKey)
            .limit(query_args.limit)
            .offset(query_args.offset)
            .order_by(via(sql.PublicSigningKey.fingerprint).asc())
        )
        paged_keys = (await data.execute(statement)).scalars().all()
        count = (
            await data.execute(sqlalchemy.select(sqlalchemy.func.count(via(sql.PublicSigningKey.fingerprint))))
        ).scalar_one()
        return models.api.KeysResults(
            endpoint="/keys",
            data=paged_keys,
            count=count,
        ).model_dump(), 200


@api.BLUEPRINT.route("/keys/ssh/add", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.KeysSshAddArgs)
@quart_schema.validate_response(models.api.KeysSshAddResults, 201)
async def keys_ssh_add(data: models.api.KeysSshAddArgs) -> DictResponse:
    """Add an SSH key for a user."""
    asf_uid = _jwt_asf_uid()
    fingerprint = await keys.ssh_key_add(data.text, asf_uid)
    return models.api.KeysSshAddResults(
        endpoint="/keys/ssh/add",
        fingerprint=fingerprint,
    ).model_dump(), 201


@api.BLUEPRINT.route("/keys/ssh/list")
@quart_schema.validate_querystring(models.api.KeysSshListQuery)
async def keys_ssh_list(query_args: models.api.KeysSshListQuery) -> DictResponse:
    """Paged list of developer SSH public keys."""
    _pagination_args_validate(query_args)
    via = sql.validate_instrumented_attribute
    async with db.session() as data:
        statement = (
            sqlmodel.select(sql.SSHKey)
            .limit(query_args.limit)
            .offset(query_args.offset)
            .order_by(via(sql.SSHKey.fingerprint).asc())
        )
        paged_keys = (await data.execute(statement)).scalars().all()

        count_stmt = sqlalchemy.select(sqlalchemy.func.count(via(sql.SSHKey.fingerprint)))
        count = (await data.execute(count_stmt)).scalar_one()

        return models.api.KeysSshListResults(
            endpoint="/keys/ssh/list",
            data=paged_keys,
            count=count,
        ).model_dump(), 200


# TODO: Call this release/paths
@api.BLUEPRINT.route("/list/<project>/<version>")
@api.BLUEPRINT.route("/list/<project>/<version>/<revision>")
@quart_schema.validate_response(models.api.ListResults, 200)
async def list_project_version(project: str, version: str, revision: str | None = None) -> DictResponse:
    _simple_check(project, version, revision)
    async with db.session() as data:
        release_name = sql.release_name(project, version)
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
    return models.api.ListResults(
        endpoint="/list",
        rel_paths=files,
    ).model_dump(), 200


@api.BLUEPRINT.route("/project/<name>")
@quart_schema.validate_response(models.api.ProjectResults, 200)
async def project(name: str) -> DictResponse:
    _simple_check(name)
    async with db.session() as data:
        project = await data.project(name=name).demand(exceptions.NotFound())
        return models.api.ProjectResults(
            endpoint="/project",
            project=project,
        ).model_dump(), 200


@api.BLUEPRINT.route("/project/releases/<name>")
@quart_schema.validate_response(models.api.ProjectReleasesResults, 200)
async def project_releases(name: str) -> DictResponse:
    """List all releases for a specific project."""
    _simple_check(name)
    async with db.session() as data:
        releases = await data.release(project_name=name).all()
        return models.api.ProjectReleasesResults(
            endpoint="/project/releases",
            releases=releases,
        ).model_dump(), 200


@api.BLUEPRINT.route("/projects")
@quart_schema.validate_response(models.api.ProjectsResults, 200)
async def projects() -> DictResponse:
    """List all projects in the database."""
    # TODO: Add pagination?
    async with db.session() as data:
        projects = await data.project().all()
        return models.api.ProjectsResults(
            endpoint="/projects",
            projects=projects,
        ).model_dump(), 200


@api.BLUEPRINT.route("/releases")
@quart_schema.validate_querystring(models.api.ReleasesQuery)
@quart_schema.validate_response(models.api.ReleasesResults, 200)
async def releases(query_args: models.api.ReleasesQuery) -> DictResponse:
    """Paged list of releases with optional filtering by phase."""
    _pagination_args_validate(query_args)
    via = sql.validate_instrumented_attribute
    async with db.session() as data:
        statement = sqlmodel.select(sql.Release)

        if query_args.phase:
            try:
                phase_value = sql.ReleasePhase(query_args.phase)
            except ValueError:
                raise exceptions.BadRequest(f"Invalid phase: {query_args.phase}")
            statement = statement.where(sql.Release.phase == phase_value)

        statement = (
            statement.order_by(via(sql.Release.created).desc()).limit(query_args.limit).offset(query_args.offset)
        )

        paged_releases = (await data.execute(statement)).scalars().all()

        count_stmt = sqlalchemy.select(sqlalchemy.func.count(via(sql.Release.name)))
        if query_args.phase:
            phase_value = sql.ReleasePhase(query_args.phase) if query_args.phase else None
            if phase_value is not None:
                count_stmt = count_stmt.where(via(sql.Release.phase) == phase_value)

        count = (await data.execute(count_stmt)).scalar_one()

        return models.api.ReleasesResults(
            endpoint="/releases",
            data=paged_releases,
            count=count,
        ).model_dump(), 200


@api.BLUEPRINT.route("/releases/create", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.ReleasesCreateArgs)
@quart_schema.validate_response(models.api.ReleasesCreateResults, 201)
async def releases_create(data: models.api.ReleasesCreateArgs) -> DictResponse:
    """Create a new release draft for a project via POSTed JSON."""
    asf_uid = _jwt_asf_uid()

    try:
        release, _project = await start.create_release_draft(
            project_name=data.project,
            version=data.version,
            asf_uid=asf_uid,
        )
    except routes.FlashError as exc:
        raise exceptions.BadRequest(str(exc))

    return models.api.ReleasesCreateResults(
        endpoint="/releases/create",
        release=release,
    ).model_dump(), 201


@api.BLUEPRINT.route("/releases/delete", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.ReleasesDeleteArgs)
@quart_schema.validate_response(models.api.ReleasesDeleteResults, 200)
async def releases_delete(data: models.api.ReleasesDeleteArgs) -> DictResponse:
    """Delete a release draft for a project via POSTed JSON."""
    asf_uid = _jwt_asf_uid()
    if not user.is_admin(asf_uid):
        raise exceptions.Forbidden("You do not have permission to create a release")

    async with db.session() as db_data:
        release_name = sql.release_name(data.project, data.version)
        await interaction.release_delete(release_name, include_downloads=True)
        await db_data.commit()
    return models.api.ReleasesDeleteResults(
        endpoint="/releases/delete",
        deleted=release_name,
    ).model_dump(), 200


@api.BLUEPRINT.route("/releases/project/<project>")
@quart_schema.validate_querystring(models.api.ReleasesProjectQuery)
async def releases_project(project: str, query_args: models.api.ReleasesProjectQuery) -> DictResponse:
    """List all releases for a specific project with pagination."""
    _simple_check(project)
    _pagination_args_validate(query_args)
    async with db.session() as data:
        project_result = await data.project(name=project).get()
        if project_result is None:
            raise exceptions.NotFound(f"Project '{project}' does not exist")

        via = sql.validate_instrumented_attribute
        statement = (
            sqlmodel.select(sql.Release)
            .where(sql.Release.project_name == project)
            .order_by(via(sql.Release.created).desc())
            .limit(query_args.limit)
            .offset(query_args.offset)
        )

        paged_releases = (await data.execute(statement)).scalars().all()

        count_stmt = sqlalchemy.select(sqlalchemy.func.count(via(sql.Release.name))).where(
            via(sql.Release.project_name) == project
        )
        count = (await data.execute(count_stmt)).scalar_one()

        return models.api.ReleasesProjectResults(
            endpoint="/releases/project",
            data=paged_releases,
            count=count,
        ).model_dump(), 200


# TODO: If we validate as sql.Release, quart_schema silently corrupts latest_revision_number to None
# @quart_schema.validate_response(sql.Release, 200)
@api.BLUEPRINT.route("/releases/version/<project>/<version>")
@quart_schema.validate_response(models.api.ReleasesVersionResults, 200)
async def releases_project_version(project: str, version: str) -> DictResponse:
    """Return a single release by project and version."""
    _simple_check(project, version)
    async with db.session() as data:
        release_name = sql.release_name(project, version)
        release = await data.release(name=release_name).demand(exceptions.NotFound())
        return models.api.ReleasesVersionResults(
            endpoint="/releases/version",
            release=release,
        ).model_dump(), 200


# TODO: Rename this to revisions? I.e. /revisions/<project>/<version>
@api.BLUEPRINT.route("/releases/revisions/<project>/<version>")
@quart_schema.validate_response(models.api.ReleasesRevisionsResults, 200)
async def releases_project_version_revisions(project: str, version: str) -> DictResponse:
    """List all revisions for a given release."""
    _simple_check(project, version)
    async with db.session() as data:
        release_name = sql.release_name(project, version)
        revisions = await data.revision(release_name=release_name).all()
        return models.api.ReleasesRevisionsResults(
            endpoint="/releases/revisions",
            revisions=revisions,
        ).model_dump(), 200


@api.BLUEPRINT.route("/revisions/<project>/<version>")
@quart_schema.validate_response(dict[str, list[sql.Revision]], 200)
async def revisions_project_version(project: str, version: str) -> tuple[dict[str, list[sql.Revision]], int]:
    _simple_check(project, version)
    async with db.session() as data:
        release_name = sql.release_name(project, version)
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


@api.BLUEPRINT.route("/tasks")
@quart_schema.validate_querystring(models.api.Task)
async def tasks(query_args: models.api.Task) -> quart.Response:
    _pagination_args_validate(query_args)
    via = sql.validate_instrumented_attribute
    async with db.session() as data:
        statement = sqlmodel.select(sql.Task).limit(query_args.limit).offset(query_args.offset)
        if query_args.status:
            if query_args.status not in sql.TaskStatus:
                raise exceptions.BadRequest(f"Invalid status: {query_args.status}")
            statement = statement.where(sql.Task.status == query_args.status)
        statement = statement.order_by(via(sql.Task.id).desc())
        paged_tasks = (await data.execute(statement)).scalars().all()
        count_statement = sqlalchemy.select(sqlalchemy.func.count(via(sql.Task.id)))
        if query_args.status:
            count_statement = count_statement.where(via(sql.Task.status) == query_args.status)
        count = (await data.execute(count_statement)).scalar_one()
        result = {"data": [paged_task.model_dump(exclude={"result"}) for paged_task in paged_tasks], "count": count}
        return quart.jsonify(result)


@api.BLUEPRINT.route("/vote/resolve", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.ProjectVersionResolution)
@quart_schema.validate_response(dict[str, str], 200)
async def vote_resolve(data: models.api.ProjectVersionResolution) -> tuple[Mapping, int]:
    asf_uid = _jwt_asf_uid()

    async with db.session() as db_data:
        release_name = sql.release_name(data.project, data.version)
        release = await db_data.release(name=release_name, _project=True, _committee=True).demand(exceptions.NotFound())
        if release.project.committee is None:
            raise exceptions.NotFound("Project has no committee")
        _committee_member_or_admin(release.project.committee, asf_uid)

        release = await db_data.merge(release)
        match data.resolution:
            case "passed":
                release.phase = sql.ReleasePhase.RELEASE_PREVIEW
                success_message = "Vote marked as passed"
                description = "Create a preview revision from the last candidate draft"
                async with revision.create_and_manage(
                    data.project, release.version, asf_uid, description=description
                ) as _creating:
                    pass
            case "failed":
                release.phase = sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
                success_message = "Vote marked as failed"
        await db_data.commit()
    return {"success": success_message}, 200


@api.BLUEPRINT.route("/vote/start", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.VoteStart)
@quart_schema.validate_response(sql.Task, 201)
async def vote_start(data: models.api.VoteStart) -> tuple[Mapping, int]:
    asf_uid = _jwt_asf_uid()

    permitted_recipients = util.permitted_recipients(asf_uid)
    if data.email_to not in permitted_recipients:
        raise exceptions.Forbidden("Invalid mailing list choice")

    async with db.session() as db_data:
        release_name = sql.release_name(data.project, data.version)
        release = await db_data.release(name=release_name, _project=True, _committee=True).demand(exceptions.NotFound())
        if release.project.committee is None:
            raise exceptions.NotFound("Project has no committee")
        _committee_member_or_admin(release.project.committee, asf_uid)

        revision_exists = await db_data.revision(release_name=release_name, number=data.revision).get()
        if revision_exists is None:
            raise exceptions.NotFound(f"Revision '{data.revision}' does not exist")

        error = await voting.promote_release(db_data, release_name, data.revision, vote_manual=False)
        if error:
            raise exceptions.BadRequest(error)

        # TODO: Move this into a function in routes/voting.py
        task = sql.Task(
            status=sql.TaskStatus.QUEUED,
            task_type=sql.TaskType.VOTE_INITIATE,
            task_args=tasks_vote.Initiate(
                release_name=release_name,
                email_to=data.email_to,
                vote_duration=data.vote_duration,
                initiator_id=asf_uid,
                initiator_fullname=asf_uid,
                subject=data.subject,
                body=data.body,
            ).model_dump(),
            project_name=data.project,
            version_name=data.version,
        )
        db_data.add(task)
        await db_data.commit()
        return task.model_dump(exclude={"result"}), 201


@api.BLUEPRINT.route("/upload", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.ProjectVersionRelpathContent)
@quart_schema.validate_response(sql.Revision, 201)
async def upload(data: models.api.ProjectVersionRelpathContent) -> tuple[Mapping, int]:
    asf_uid = _jwt_asf_uid()

    async with db.session() as db_data:
        project = await db_data.project(name=data.project, _committee=True).demand(exceptions.NotFound())
        # TODO: user.is_participant(project, asf_uid)
        if not (user.is_committee_member(project.committee, asf_uid) or user.is_admin(asf_uid)):
            raise exceptions.Forbidden("You do not have permission to upload to this project")

    revision = await _upload_process_file(data, asf_uid)
    return revision.model_dump(), 201


def _committee_member_or_admin(committee: sql.Committee, asf_uid: str) -> None:
    if not (user.is_committee_member(committee, asf_uid) or user.is_admin(asf_uid)):
        raise exceptions.Forbidden("You do not have permission to perform this action")


@db.session_function
async def _get_pat(data: db.Session, uid: str, token_hash: str) -> sql.PersonalAccessToken | None:
    return await data.query_one_or_none(
        sqlmodel.select(sql.PersonalAccessToken).where(
            sql.PersonalAccessToken.asfuid == uid,
            sql.PersonalAccessToken.token_hash == token_hash,
        )
    )


def _jwt_asf_uid() -> str:
    claims = getattr(quart.g, "jwt_claims", {})
    asf_uid = claims.get("sub")
    if not isinstance(asf_uid, str):
        raise base.ASFQuartException("Invalid token subject", errorcode=401)
    return asf_uid


def _pagination_args_validate(query_args: Any) -> None:
    # Users could request any amount using limit=N with arbitrarily high N
    # We therefore limit the maximum limit to 1000
    if hasattr(query_args, "limit") and (query_args.limit > 1000):
        # quart.abort(400, "Limit is too high")
        raise exceptions.BadRequest("Maximum limit of 1000 exceeded")


def _simple_check(*args: str | None) -> None:
    for arg in args:
        if arg == "None":
            raise exceptions.BadRequest("Argument cannot be the string 'None'")


async def _upload_process_file(args: models.api.ProjectVersionRelpathContent, asf_uid: str) -> sql.Revision:
    file_bytes = base64.b64decode(args.content, validate=True)
    file_path = args.relpath.lstrip("/")
    description = f"Upload via API: {file_path}"
    async with revision.create_and_manage(args.project, args.version, asf_uid, description=description) as creating:
        target_path = pathlib.Path(creating.interim_path) / file_path
        await aiofiles.os.makedirs(target_path.parent, exist_ok=True)
        async with aiofiles.open(target_path, "wb") as f:
            await f.write(file_bytes)
    if creating.new is None:
        raise exceptions.InternalServerError("Failed to create revision")
    async with db.session() as data:
        release_name = sql.release_name(args.project, args.version)
        return await data.revision(release_name=release_name, number=creating.new.number).demand(exceptions.NotFound())
