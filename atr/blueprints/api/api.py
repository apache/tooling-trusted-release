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


import hashlib
import pathlib
from typing import Any

import aiofiles.os
import asfquart.base as base
import pgpy
import quart
import quart_schema
import sqlalchemy
import sqlmodel
import werkzeug.exceptions as exceptions

import atr.blueprints.api as api
import atr.config as config
import atr.db as db
import atr.db.interaction as interaction
import atr.jwtoken as jwtoken
import atr.models as models
import atr.models.sql as sql
import atr.storage as storage
import atr.storage.outcome as outcome
import atr.storage.types as types
import atr.tabulate as tabulate
import atr.user as user
import atr.util as util

# FIXME: we need to return the dumped model instead of the actual pydantic class
#        as otherwise pyright will complain about the return type
#        it would work though, see https://github.com/pgjones/quart-schema/issues/91
#        For now, just explicitly dump the model.

# We implicitly have /api/openapi.json

DictResponse = tuple[dict[str, Any], int]


@api.BLUEPRINT.route("/checks/list/<project>/<version>")
@quart_schema.validate_response(models.api.ChecksListResults, 200)
async def checks_list(project: str, version: str) -> DictResponse:
    """
    List checks by project and version.

    Checks are only conducted during the compose a draft phase. This endpoint
    only returns the checks for the most recent draft revision. Once a release
    has been promoted to the vote phase or beyond, the checks returned are
    still those for the compose phase.

    Warning: the check results include results for archive members, so there
    may potentially be thousands or results or more.
    """
    # TODO: We should perhaps paginate this
    # TODO: Add phase in the response, and the revision too
    _simple_check(project, version)
    # TODO: Merge with checks_list_project_version_revision
    async with db.session() as data:
        release_name = sql.release_name(project, version)
        release = await data.release(name=release_name).demand(exceptions.NotFound(f"Release {release_name} not found"))
        check_results = await data.check_result(release_name=release_name).all()

    revision = None
    for check_result in check_results:
        if revision is None:
            revision = check_result.revision_number
        elif revision != check_result.revision_number:
            raise exceptions.InternalServerError("Revision mismatch")
    if revision is None:
        raise exceptions.InternalServerError("No revision found")

    return models.api.ChecksListResults(
        endpoint="/checks/list",
        checks=check_results,
        checks_revision=revision,
        current_phase=release.phase,
    ).model_dump(), 200


@api.BLUEPRINT.route("/checks/list/<project>/<version>/<revision>")
@quart_schema.validate_response(models.api.ChecksListResults, 200)
async def checks_list_revision(project: str, version: str, revision: str) -> DictResponse:
    """
    List checks by project, version, and revision.

    Checks are only conducted during the compose a draft phase. This endpoint
    only returns the checks for the specified draft revision. Once a release
    has been promoted to the vote phase or beyond, the checks returned are
    still those for the specified revision from the compose phase.

    Warning: the check results include results for archive members, so there
    may potentially be thousands or results or more.
    """
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
        checks_revision=revision,
        current_phase=release_result.phase,
    ).model_dump(), 200


@api.BLUEPRINT.route("/checks/ongoing/<project>/<version>", defaults={"revision": None})
@api.BLUEPRINT.route("/checks/ongoing/<project>/<version>/<revision>")
@quart_schema.validate_response(models.api.ChecksOngoingResults, 200)
async def checks_ongoing(
    project: str,
    version: str,
    revision: str | None = None,
) -> DictResponse:
    """
    Count ongoing checks by project, version, and optionally revision.

    Checks are only conducted during the compose a draft phase. This endpoint
    returns the number of ongoing checks for the specified draft revision if
    present, or the most recent draft revision otherwise. A draft release
    cannot be promoted to the vote phase if checks are still ongoing.
    """
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


@api.BLUEPRINT.route("/committee/get/<name>")
@quart_schema.validate_response(models.api.CommitteeGetResults, 200)
async def committee_get(name: str) -> DictResponse:
    """
    Get a committee by name.

    The name of the committee is the name without any prefixes or suffixes such
    as "Apache" or "PMC", in lower case, and with hyphens instead of spaces.
    The Apache Simple Example PMC, for example, would have the name
    "simple-example".
    """
    _simple_check(name)
    async with db.session() as data:
        committee = await data.committee(name=name).demand(exceptions.NotFound(f"Committee '{name}' was not found"))
    return models.api.CommitteeGetResults(
        endpoint="/committee/get",
        committee=committee,
    ).model_dump(), 200


@api.BLUEPRINT.route("/committee/keys/<name>")
@quart_schema.validate_response(models.api.CommitteeKeysResults, 200)
async def committee_keys(name: str) -> DictResponse:
    """
    List public OpenPGP keys by committee name.

    The name of the committee is the name without any prefixes or suffixes such
    as "Apache" or "PMC", in lower case, and with hyphens instead of spaces.
    The Apache Simple Example PMC, for example, would have the name
    "simple-example".
    """
    _simple_check(name)
    async with db.session() as data:
        committee = await data.committee(name=name, _public_signing_keys=True).demand(
            exceptions.NotFound(f"Committee '{name}' was not found")
        )
    return models.api.CommitteeKeysResults(
        endpoint="/committee/keys",
        keys=committee.public_signing_keys,
    ).model_dump(), 200


@api.BLUEPRINT.route("/committee/projects/<name>")
@quart_schema.validate_response(models.api.CommitteeProjectsResults, 200)
async def committee_projects(name: str) -> DictResponse:
    """
    List projects by committee name.

    The name of the committee is the name without any prefixes or suffixes such
    as "Apache" or "PMC", in lower case, and with hyphens instead of spaces.
    The Apache Simple Example PMC, for example, would have the name
    "simple-example".
    """
    _simple_check(name)
    async with db.session() as data:
        committee = await data.committee(name=name, _projects=True).demand(
            exceptions.NotFound(f"Committee '{name}' was not found")
        )
    return models.api.CommitteeProjectsResults(
        endpoint="/committee/projects",
        projects=committee.projects,
    ).model_dump(), 200


@api.BLUEPRINT.route("/committees/list")
@quart_schema.validate_response(models.api.CommitteesListResults, 200)
async def committees_list() -> DictResponse:
    """
    List committees.

    The list of committees is returned in no particular order.
    """
    async with db.session() as data:
        committees = await data.committee().all()
    return models.api.CommitteesListResults(
        endpoint="/committees/list",
        committees=committees,
    ).model_dump(), 200


@api.BLUEPRINT.route("/distribution/record", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.DistributionRecordArgs)
@quart_schema.validate_response(models.api.DistributionRecordResults, 200)
async def distribution_record(data: models.api.DistributionRecordArgs) -> DictResponse:
    """
    Record a distribution.
    """
    asf_uid = _jwt_asf_uid()
    async with db.session() as db_data:
        release_name = models.sql.release_name(data.project, data.version)
        release = await db_data.release(
            project_name=data.project,
            version=data.version,
        ).demand(exceptions.NotFound(f"Release {release_name} not found"))
    if release.committee is None:
        raise exceptions.NotFound(f"Release {release_name} has no committee")
    dd = models.distribution.Data(
        platform=data.platform,
        owner_namespace=data.distribution_owner_namespace,
        package=data.distribution_package,
        version=data.distribution_version,
        details=data.details,
    )
    async with storage.write(asf_uid) as write:
        wacm = write.as_committee_member(release.committee.name)
        await wacm.distributions.record_from_data(
            release,
            data.staging,
            dd,
        )

    return models.api.DistributionRecordResults(
        endpoint="/distribution/record",
        success=True,
    ).model_dump(), 200


@api.BLUEPRINT.route("/ignore/add", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.IgnoreAddArgs)
@quart_schema.validate_response(models.api.IgnoreAddResults, 200)
async def ignore_add(data: models.api.IgnoreAddArgs) -> DictResponse:
    """
    Add a check ignore.
    """
    asf_uid = _jwt_asf_uid()
    if not any(data.model_dump().values()):
        raise exceptions.BadRequest("At least one field must be provided")
    async with storage.write(asf_uid) as write:
        wacm = write.as_committee_member(data.committee_name)
        await wacm.checks.ignore_add(
            data.release_glob,
            data.revision_number,
            data.checker_glob,
            data.primary_rel_path_glob,
            data.member_rel_path_glob,
            data.status,
            data.message_glob,
        )
    return models.api.IgnoreAddResults(
        endpoint="/ignore/add",
        success=True,
    ).model_dump(), 200


@api.BLUEPRINT.route("/ignore/delete", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.IgnoreDeleteArgs)
@quart_schema.validate_response(models.api.IgnoreDeleteResults, 200)
async def ignore_delete(data: models.api.IgnoreDeleteArgs) -> DictResponse:
    """
    Delete a check ignore.
    """
    asf_uid = _jwt_asf_uid()
    if not any(data.model_dump().values()):
        raise exceptions.BadRequest("At least one field must be provided")
    async with storage.write(asf_uid) as write:
        wacm = write.as_committee_member(data.committee)
        # TODO: This is more like discard
        # Should potentially check for rowcount, and raise an error if it's 0
        await wacm.checks.ignore_delete(data.id)
    return models.api.IgnoreDeleteResults(
        endpoint="/ignore/delete",
        success=True,
    ).model_dump(), 200


# TODO: Rename to ignores
@api.BLUEPRINT.route("/ignore/list/<committee_name>")
@quart_schema.validate_response(models.api.IgnoreListResults, 200)
async def ignore_list(committee_name: str) -> DictResponse:
    """
    List ignores by committee name.
    """
    _simple_check(committee_name)
    async with db.session() as data:
        ignores = await data.check_result_ignore(committee_name=committee_name).all()
    return models.api.IgnoreListResults(
        endpoint="/ignore/list",
        ignores=ignores,
    ).model_dump(), 200


@api.BLUEPRINT.route("/jwt/create", methods=["POST"])
@quart_schema.validate_request(models.api.JwtCreateArgs)
async def jwt_create(data: models.api.JwtCreateArgs) -> DictResponse:
    """
    Create a JWT.

    The payload must include a valid PAT.
    """
    # Expects {"asfuid": "uid", "pat": "pat-token"}
    # Returns {"asfuid": "uid", "jwt": "jwt-token"}
    asf_uid = data.asfuid
    async with storage.write(asf_uid) as write:
        wafc = write.as_foundation_committer()
        jwt = await wafc.tokens.issue_jwt(data.pat)

    return models.api.JwtCreateResults(
        endpoint="/jwt/create",
        asfuid=data.asfuid,
        jwt=jwt,
    ).model_dump(), 200


@api.BLUEPRINT.route("/key/add", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.KeyAddArgs)
@quart_schema.validate_response(models.api.KeyAddResults, 200)
async def key_add(data: models.api.KeyAddArgs) -> DictResponse:
    """
    Add a public OpenPGP key.

    Once associated with the specified committees, the key will appear in the
    automatically generated KEYS file for each committee.
    """
    asf_uid = _jwt_asf_uid()
    selected_committee_names = data.committees

    async with storage.write(asf_uid) as write:
        wafc = write.as_foundation_committer()
        ocr: outcome.Outcome[types.Key] = await wafc.keys.ensure_stored_one(data.key)
        key = ocr.result_or_raise()

        for selected_committee_name in selected_committee_names:
            wacm = write.as_committee_member(selected_committee_name)
            oc: outcome.Outcome[types.LinkedCommittee] = await wacm.keys.associate_fingerprint(
                key.key_model.fingerprint
            )
            oc.result_or_raise()

    return models.api.KeyAddResults(
        endpoint="/key/add",
        fingerprint=key.key_model.fingerprint.upper(),
    ).model_dump(), 200


@api.BLUEPRINT.route("/key/delete", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.KeyDeleteArgs)
@quart_schema.validate_response(models.api.KeyDeleteResults, 200)
async def key_delete(data: models.api.KeyDeleteArgs) -> DictResponse:
    """
    Delete a public OpenPGP key.

    Warning: we plan to change how key deletion works.
    """
    asf_uid = _jwt_asf_uid()
    fingerprint = data.fingerprint.lower()

    outcomes = outcome.List[str]()
    async with storage.write(asf_uid) as write:
        wafc = write.as_foundation_committer()
        oc: outcome.Outcome[sql.PublicSigningKey] = await wafc.keys.delete_key(fingerprint)
        key = oc.result_or_raise()

        for committee in key.committees:
            wacm = write.as_committee_member_outcome(committee.name).result_or_none()
            if wacm is None:
                continue
            outcomes.append(await wacm.keys.autogenerate_keys_file())
    # TODO: Add error outcomes as warnings to the response

    return models.api.KeyDeleteResults(
        endpoint="/key/delete",
        success=True,
    ).model_dump(), 200


@api.BLUEPRINT.route("/key/get/<fingerprint>")
@quart_schema.validate_response(models.api.KeyGetResults, 200)
async def key_get(fingerprint: str) -> DictResponse:
    """
    Get a public OpenPGP key by fingerprint.

    All public OpenPGP keys stored within the database are accessible.
    """
    _simple_check(fingerprint)
    async with db.session() as data:
        key = await data.public_signing_key(fingerprint=fingerprint.lower()).demand(
            exceptions.NotFound(f"Key '{fingerprint}' not found")
        )
    return models.api.KeyGetResults(
        endpoint="/key/get",
        key=key,
    ).model_dump(), 200


@api.BLUEPRINT.route("/keys/upload", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.KeysUploadArgs)
@quart_schema.validate_response(models.api.KeysUploadResults, 200)
async def keys_upload(data: models.api.KeysUploadArgs) -> DictResponse:
    """
    Upload a public OpenPGP KEYS file.
    """
    asf_uid = _jwt_asf_uid()
    filetext = data.filetext
    selected_committee_name = data.committee
    async with storage.write(asf_uid) as write:
        wacm = write.as_committee_member(selected_committee_name)
        outcomes: outcome.List[types.Key] = await wacm.keys.ensure_associated(filetext)

        # TODO: It would be nice to serialise the actual outcomes
        # Or, perhaps better yet, to have a standard datatype mapping
        # This would be specified in models.api, then imported into storage.types
        # Or perhaps it should go in models.storage or models.outcomes
        api_outcomes = []
        for oc in outcomes.outcomes():
            api_outcome: models.api.KeysUploadOutcome | None = None
            match oc:
                case outcome.Result(result):
                    api_outcome = models.api.KeysUploadResult(
                        status="success",
                        key=result.key_model,
                    )
                case outcome.Error(error):
                    # TODO: This branch means we must improve the return type
                    match error:
                        case types.PublicKeyError() as pke:
                            api_outcome = models.api.KeysUploadException(
                                status="error",
                                key=pke.key.key_model,
                                error=str(pke),
                                error_type=type(pke).__name__,
                            )
                        case _ as e:
                            api_outcome = models.api.KeysUploadException(
                                status="error",
                                key=None,
                                error=str(e),
                                error_type=type(e).__name__,
                            )
            # Type checker is sure that it can no longer be None
            api_outcomes.append(api_outcome)
    return models.api.KeysUploadResults(
        endpoint="/keys/upload",
        results=api_outcomes,
        success_count=outcomes.result_count,
        error_count=outcomes.error_count,
        submitted_committee=selected_committee_name,
    ).model_dump(), 200


@api.BLUEPRINT.route("/keys/user/<asf_uid>")
@quart_schema.validate_response(models.api.KeysUserResults, 200)
async def keys_user(asf_uid: str) -> DictResponse:
    """
    List public OpenPGP keys by the ASF UID of a user.
    """
    _simple_check(asf_uid)
    async with db.session() as data:
        keys = await data.public_signing_key(apache_uid=asf_uid).all()
    return models.api.KeysUserResults(
        endpoint="/keys/user",
        keys=keys,
    ).model_dump(), 200


@api.BLUEPRINT.route("/project/get/<name>")
@quart_schema.validate_response(models.api.ProjectGetResults, 200)
async def project_get(name: str) -> DictResponse:
    """
    Get a project by name.
    """
    _simple_check(name)
    async with db.session() as data:
        project = await data.project(name=name).demand(exceptions.NotFound())
    return models.api.ProjectGetResults(
        endpoint="/project/get",
        project=project,
    ).model_dump(), 200


@api.BLUEPRINT.route("/project/releases/<name>")
@quart_schema.validate_response(models.api.ProjectReleasesResults, 200)
async def project_releases(name: str) -> DictResponse:
    """
    List releases by project name.
    """
    _simple_check(name)
    async with db.session() as data:
        releases = await data.release(project_name=name).all()
    return models.api.ProjectReleasesResults(
        endpoint="/project/releases",
        releases=releases,
    ).model_dump(), 200


@api.BLUEPRINT.route("/projects/list")
@quart_schema.validate_response(models.api.ProjectsListResults, 200)
async def projects_list() -> DictResponse:
    """
    List projects.
    """
    # TODO: Add pagination?
    async with db.session() as data:
        projects = await data.project().all()
    return models.api.ProjectsListResults(
        endpoint="/projects/list",
        projects=projects,
    ).model_dump(), 200


@api.BLUEPRINT.route("/publisher/distribution/record", methods=["POST"])
@quart_schema.validate_request(models.api.PublisherDistributionRecordArgs)
async def publisher_distribution_record(data: models.api.PublisherDistributionRecordArgs) -> DictResponse:
    """
    Record a distribution with a corroborating Trusted Publisher JWT.
    """
    try:
        _payload, asf_uid, project = await interaction.trusted_jwt(
            data.publisher,
            data.jwt,
            interaction.TrustedProjectPhase.FINISH,
        )
    except interaction.ReleasePolicyNotFoundError:
        # TODO: We could perform a more advanced query with multiple in_ statements
        _payload, asf_uid, project = await interaction.trusted_jwt(
            data.publisher,
            data.jwt,
            interaction.TrustedProjectPhase.COMPOSE,
        )
    async with db.session() as db_data:
        release_name = models.sql.release_name(project.name, data.version)
        release = await db_data.release(
            project_name=project.name,
            version=data.version,
        ).demand(exceptions.NotFound(f"Release {release_name} not found"))
    if release.committee is None:
        raise exceptions.NotFound(f"Release {release_name} has no committee")
    dd = models.distribution.Data(
        platform=data.platform,
        owner_namespace=data.distribution_owner_namespace,
        package=data.distribution_package,
        version=data.distribution_version,
        details=data.details,
    )
    async with storage.write(asf_uid) as write:
        wacm = write.as_committee_member(release.committee.name)
        await wacm.distributions.record_from_data(
            release,
            data.staging,
            dd,
        )

    return models.api.PublisherDistributionRecordResults(
        endpoint="/publisher/distribution/record",
        success=True,
    ).model_dump(), 200


@api.BLUEPRINT.route("/publisher/release/announce", methods=["POST"])
@quart_schema.validate_request(models.api.PublisherReleaseAnnounceArgs)
async def publisher_release_announce(data: models.api.PublisherReleaseAnnounceArgs) -> DictResponse:
    """
    Announce a release with a corroborating Trusted Publisher JWT.
    """
    _payload, asf_uid, project = await interaction.trusted_jwt(
        data.publisher,
        data.jwt,
        interaction.TrustedProjectPhase.FINISH,
    )
    try:
        # TODO: Add defaults
        committee = util.unwrap(project.committee)
        async with storage.write_as_committee_member(committee.name, asf_uid) as wacm:
            await wacm.announce.release(
                project.name,
                data.version,
                data.revision,
                data.email_to,
                data.subject,
                data.body,
                data.path_suffix,
                asf_uid,
                asf_uid,
            )
    except storage.AccessError as e:
        raise exceptions.BadRequest(str(e))

    return models.api.PublisherReleaseAnnounceResults(
        endpoint="/publisher/release/announce",
        success=True,
    ).model_dump(), 200


@api.BLUEPRINT.route("/publisher/ssh/register", methods=["POST"])
@quart_schema.validate_request(models.api.PublisherSshRegisterArgs)
async def publisher_ssh_register(data: models.api.PublisherSshRegisterArgs) -> DictResponse:
    """
    Register an SSH key sent with a corroborating Trusted Publisher JWT.
    """
    payload, asf_uid, project = await interaction.trusted_jwt(
        data.publisher, data.jwt, interaction.TrustedProjectPhase.COMPOSE
    )
    async with storage.write_as_committee_member(util.unwrap(project.committee).name, asf_uid) as wacm:
        fingerprint, expires = await wacm.ssh.add_workflow_key(
            payload["actor"],
            payload["actor_id"],
            project.name,
            data.ssh_key,
        )

    return models.api.PublisherSshRegisterResults(
        endpoint="/publisher/ssh/register",
        fingerprint=fingerprint,
        project=project.name,
        expires=expires,
    ).model_dump(), 200


@api.BLUEPRINT.route("/publisher/vote/resolve", methods=["POST"])
@quart_schema.validate_request(models.api.PublisherVoteResolveArgs)
async def publisher_vote_resolve(data: models.api.PublisherVoteResolveArgs) -> DictResponse:
    """
    Resolve a vote with a corroborating Trusted Publisher JWT.
    """
    # TODO: Need to be able to resolve and make the release immutable
    _payload, asf_uid, project = await interaction.trusted_jwt(
        data.publisher,
        data.jwt,
        interaction.TrustedProjectPhase.VOTE,
    )
    async with storage.write_as_project_committee_member(project.name, asf_uid) as wacm:
        # TODO: Get fullname and use instead of asf_uid
        # TODO: Add resolution templating to atr.construct
        _release, _voting_round, _success_message, _error_message = await wacm.vote.resolve(
            project.name,
            data.version,
            data.resolution,
            asf_uid,
            f"The vote {data.resolution}.",
        )

    return models.api.PublisherVoteResolveResults(
        endpoint="/publisher/vote/resolve",
        success=True,
    ).model_dump(), 200


@api.BLUEPRINT.route("/release/announce", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.ReleaseAnnounceArgs)
@quart_schema.validate_response(models.api.ReleaseAnnounceResults, 201)
async def release_announce(data: models.api.ReleaseAnnounceArgs) -> DictResponse:
    """
    Announce a release.

    After a vote on a release has passed, if everything is in order and all
    paths are correct, the release can be announced. This will send an email to
    the specified announement address, and promote the release to the finished
    release phase. Once announced, a release is final and cannot be changed.
    """
    asf_uid = _jwt_asf_uid()

    try:
        async with storage.write_as_project_committee_member(data.project, asf_uid) as wacm:
            # TODO: Get fullname and use it instead of asf_uid
            await wacm.announce.release(
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
    except storage.AccessError as e:
        raise exceptions.BadRequest(str(e))

    return models.api.ReleaseAnnounceResults(
        endpoint="/release/announce",
        success=True,
    ).model_dump(), 201


@api.BLUEPRINT.route("/release/create", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.ReleaseCreateArgs)
@quart_schema.validate_response(models.api.ReleaseCreateResults, 201)
async def release_create(data: models.api.ReleaseCreateArgs) -> DictResponse:
    """
    Create a release.

    Release are created as a draft, which must be composed.
    """
    asf_uid = _jwt_asf_uid()

    try:
        async with storage.write(asf_uid) as write:
            wacp = await write.as_project_committee_participant(data.project)
            release, _project = await wacp.release.start(data.project, data.version)
    except storage.AccessError as e:
        raise exceptions.BadRequest(str(e))

    return models.api.ReleaseCreateResults(
        endpoint="/release/create",
        release=release,
    ).model_dump(), 201


# TODO: Duplicates the below
@api.BLUEPRINT.route("/release/delete", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.ReleaseDeleteArgs)
@quart_schema.validate_response(models.api.ReleaseDeleteResults, 200)
async def release_delete(data: models.api.ReleaseDeleteArgs) -> DictResponse:
    """
    Delete a release.
    """
    asf_uid = _jwt_asf_uid()
    if not user.is_admin(asf_uid):
        raise exceptions.Forbidden("You do not have permission to create a release")

    async with storage.write(asf_uid) as write:
        wafa = write.as_foundation_admin(data.project)
        await wafa.release.delete(data.project, data.version)
    return models.api.ReleaseDeleteResults(
        endpoint="/release/delete",
        deleted=True,
    ).model_dump(), 200


@api.BLUEPRINT.route("/release/get/<project>/<version>")
@quart_schema.validate_response(models.api.ReleaseGetResults, 200)
async def release_get(project: str, version: str) -> DictResponse:
    """
    Get a release by project and version.
    """
    _simple_check(project, version)
    async with db.session() as data:
        release_name = sql.release_name(project, version)
        release = await data.release(name=release_name).demand(exceptions.NotFound())
    return models.api.ReleaseGetResults(
        endpoint="/release/get",
        release=release,
    ).model_dump(), 200


@api.BLUEPRINT.route("/release/paths/<project>/<version>")
@api.BLUEPRINT.route("/release/paths/<project>/<version>/<revision>")
@quart_schema.validate_response(models.api.ReleasePathsResults, 200)
async def release_paths(project: str, version: str, revision: str | None = None) -> DictResponse:
    """
    List paths in a release by project and version.
    """
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
    return models.api.ReleasePathsResults(
        endpoint="/release/paths",
        rel_paths=files,
    ).model_dump(), 200


@api.BLUEPRINT.route("/release/revisions/<project>/<version>")
@quart_schema.validate_response(models.api.ReleaseRevisionsResults, 200)
async def release_revisions(project: str, version: str) -> DictResponse:
    """
    List revisions by project and version.
    """
    _simple_check(project, version)
    async with db.session() as data:
        release_name = sql.release_name(project, version)
        revisions = await data.revision(release_name=release_name).all()
    if not isinstance(revisions, list):
        revisions = list(revisions)
    revisions.sort(key=lambda rev: rev.number)
    return models.api.ReleaseRevisionsResults(
        endpoint="/release/revisions",
        revisions=revisions,
    ).model_dump(), 200


@api.BLUEPRINT.route("/release/upload", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.ReleaseUploadArgs)
@quart_schema.validate_response(models.api.ReleaseUploadResults, 201)
async def release_upload(data: models.api.ReleaseUploadArgs) -> DictResponse:
    """
    Upload a file to a release.
    """
    asf_uid = _jwt_asf_uid()

    # async with db.session() as db_data:
    #     project = await db_data.project(name=data.project, _committee=True).demand(exceptions.NotFound())
    #     # TODO: user.is_participant(project, asf_uid)
    #     if not (user.is_committee_member(project.committee, asf_uid) or user.is_admin(asf_uid)):
    #         raise exceptions.Forbidden("You do not have permission to upload to this project")

    async with storage.write(asf_uid) as write:
        wacp = await write.as_project_committee_participant(data.project)
        revision = await wacp.release.upload_file(data)
    return models.api.ReleaseUploadResults(
        endpoint="/release/upload",
        revision=revision,
    ).model_dump(), 201


@api.BLUEPRINT.route("/releases/list")
@quart_schema.validate_querystring(models.api.ReleasesListQuery)
@quart_schema.validate_response(models.api.ReleasesListResults, 200)
async def releases_list(query_args: models.api.ReleasesListQuery) -> DictResponse:
    """
    List releases.

    The list of releases is paged and can be filtered by phase.
    """
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

    return models.api.ReleasesListResults(
        endpoint="/releases/list",
        data=paged_releases,
        count=count,
    ).model_dump(), 200


@api.BLUEPRINT.route("/signature/provenance", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.SignatureProvenanceArgs)
@quart_schema.validate_response(models.api.SignatureProvenanceResults, 200)
async def signature_provenance(data: models.api.SignatureProvenanceArgs) -> DictResponse:
    """
    Get the provenance of a signature.
    """
    # POST because this uses significant computation and I/O
    # We receive a file name and an SHA3-256 hash
    # From these we find which committee(s) published the file with a signature
    # Then we deliver the appropriate signing key from the KEYS file(s)
    # And the URL of the KEYS file(s) for them to check

    signing_keys: list[models.api.SignatureProvenanceKey] = []
    conf = config.get()
    host = conf.APP_HOST

    signature_asc_data = data.signature_asc_text
    sig = pgpy.PGPSignature.from_blob(signature_asc_data)

    if not hasattr(sig, "signer_fingerprint"):
        raise exceptions.NotFound("No signer fingerprint found")

    signer_fingerprint = getattr(sig, "signer_fingerprint").lower()
    async with db.session() as db_data:
        key = await db_data.public_signing_key(
            fingerprint=signer_fingerprint,
            _committees=True,
        ).demand(
            exceptions.NotFound(
                f"Key with fingerprint {signer_fingerprint} not found",
            )
        )

    downloads_dir = util.get_downloads_dir()
    matched_committee_names = await _match_committee_names(key.committees, util.get_finished_dir(), data)

    for matched_committee_name in matched_committee_names:
        keys_file_path = downloads_dir / matched_committee_name / "KEYS"
        async with aiofiles.open(keys_file_path, "rb") as f:
            keys_file_data = await f.read()
        keys_file_sha3_256 = hashlib.sha3_256(keys_file_data).hexdigest()
        signing_keys.append(
            models.api.SignatureProvenanceKey(
                committee=matched_committee_name,
                keys_file_url=f"https://{host}/downloads/{matched_committee_name}/KEYS",
                keys_file_sha3_256=keys_file_sha3_256,
            )
        )

    if not signing_keys:
        raise exceptions.NotFound("No signing keys found")

    return models.api.SignatureProvenanceResults(
        endpoint="/signature/provenance",
        fingerprint=signer_fingerprint,
        key_asc_text=key.ascii_armored_key,
        committees_with_artifact=signing_keys,
    ).model_dump(), 200


@api.BLUEPRINT.route("/ssh-key/add", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.SshKeyAddArgs)
@quart_schema.validate_response(models.api.SshKeyAddResults, 201)
async def ssh_key_add(data: models.api.SshKeyAddArgs) -> DictResponse:
    """
    Add an SSH key.

    An SSH key is associated with a single user.
    """
    asf_uid = _jwt_asf_uid()
    async with storage.write(asf_uid) as write:
        wafc = write.as_foundation_committer()
        fingerprint = await wafc.ssh.add_key(data.text, asf_uid)
    return models.api.SshKeyAddResults(
        endpoint="/ssh-key/add",
        fingerprint=fingerprint,
    ).model_dump(), 201


@api.BLUEPRINT.route("/ssh-key/delete", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.SshKeyDeleteArgs)
@quart_schema.validate_response(models.api.SshKeyDeleteResults, 201)
async def ssh_key_delete(data: models.api.SshKeyDeleteArgs) -> DictResponse:
    """
    Delete an SSH key.

    An SSH key can only be deleted by the user who owns it.
    """
    asf_uid = _jwt_asf_uid()
    async with storage.write(asf_uid) as write:
        wafc = write.as_foundation_committer()
        await wafc.ssh.delete_key(data.fingerprint)
    return models.api.SshKeyDeleteResults(
        endpoint="/ssh-key/delete",
        success=True,
    ).model_dump(), 201


@api.BLUEPRINT.route("/ssh-keys/list/<asf_uid>")
@quart_schema.validate_querystring(models.api.SshKeysListQuery)
async def ssh_keys_list(asf_uid: str, query_args: models.api.SshKeysListQuery) -> DictResponse:
    """
    List SSH keys by ASF UID.
    """
    _simple_check(asf_uid)
    _pagination_args_validate(query_args)
    via = sql.validate_instrumented_attribute
    async with db.session() as data:
        statement = (
            sqlmodel.select(sql.SSHKey)
            .where(sql.SSHKey.asf_uid == asf_uid)
            .limit(query_args.limit)
            .offset(query_args.offset)
            .order_by(via(sql.SSHKey.fingerprint).asc())
        )
        paged_keys = (await data.execute(statement)).scalars().all()

        count_stmt = sqlalchemy.select(sqlalchemy.func.count(via(sql.SSHKey.fingerprint)))
        count = (await data.execute(count_stmt)).scalar_one()

    return models.api.SshKeysListResults(
        endpoint="/ssh-keys/list",
        data=paged_keys,
        count=count,
    ).model_dump(), 200


@api.BLUEPRINT.route("/tasks/list")
@quart_schema.validate_querystring(models.api.TasksListQuery)
async def tasks_list(query_args: models.api.TasksListQuery) -> DictResponse:
    """
    List tasks.
    """
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
    return models.api.TasksListResults(
        endpoint="/tasks/list",
        data=paged_tasks,
        count=count,
    ).model_dump(), 200


@api.BLUEPRINT.route("/users/list")
@quart_schema.validate_response(models.api.UsersListResults, 200)
async def users_list() -> DictResponse:
    """
    List known users.

    This is not a list of all ASF users, but only those known to ATR.
    """
    # It is not even a list of users who have logged in to ATR
    # Only those who has stored certain kinds of data:
    # PersonalAccessToken.asfuid
    # SSHKey.asf_uid
    # PublicSigningKey.apache_uid
    # Revision.asfuid
    async with db.session() as data:
        # TODO: Combine these queries
        via = sql.validate_instrumented_attribute
        result = await data.execute(sqlalchemy.select(via(sql.PersonalAccessToken.asfuid)).distinct())
        pat_uids = set(result.scalars().all())

        result = await data.execute(sqlalchemy.select(via(sql.SSHKey.asf_uid)).distinct())
        ssh_uids = set(result.scalars().all())

        result = await data.execute(sqlalchemy.select(via(sql.PublicSigningKey.apache_uid)).distinct())
        public_signing_uids = set(result.scalars().all())

        result = await data.execute(sqlalchemy.select(via(sql.Revision.asfuid)).distinct())
        revision_uids = set(result.scalars().all())

        users = pat_uids | ssh_uids | public_signing_uids | revision_uids
        users -= {None}
    return models.api.UsersListResults(
        endpoint="/users/list",
        users=sorted(users),
    ).model_dump(), 200


# TODO: Add endpoints to allow users to vote
@api.BLUEPRINT.route("/vote/resolve", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.VoteResolveArgs)
@quart_schema.validate_response(models.api.VoteResolveResults, 200)
async def vote_resolve(data: models.api.VoteResolveArgs) -> DictResponse:
    """
    Resolve a vote.

    A vote can be resolved by passing or failing.
    """
    asf_uid = _jwt_asf_uid()
    # try:
    async with storage.write_as_project_committee_member(data.project, asf_uid) as wacm:
        # TODO: Get fullname and use instead of asf_uid
        # TODO: Add resolution templating to atr.construct
        _release, _voting_round, _success_message, _error_message = await wacm.vote.resolve(
            data.project,
            data.version,
            data.resolution,
            asf_uid,
            f"The vote {data.resolution}.",
        )
    # except Exception as e:
    #     import atr.log as log
    #     import traceback
    #     log.info(traceback.format_exc())
    #     raise exceptions.BadRequest(str(e))

    return models.api.VoteResolveResults(
        endpoint="/vote/resolve",
        success=True,
    ).model_dump(), 200


@api.BLUEPRINT.route("/vote/start", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.VoteStartArgs)
@quart_schema.validate_response(models.api.VoteStartResults, 201)
async def vote_start(data: models.api.VoteStartArgs) -> DictResponse:
    """
    Start a vote.
    """
    asf_uid = _jwt_asf_uid()

    try:
        async with storage.write(asf_uid) as write:
            wacp = await write.as_project_committee_participant(data.project)
            permitted_recipients = util.permitted_voting_recipients(asf_uid, wacp.committee_name)
            if data.email_to not in permitted_recipients:
                raise exceptions.Forbidden("Invalid mailing list choice")
            # TODO: Get fullname and use instead of asf_uid
            task = await wacp.vote.start(
                data.email_to,
                data.project,
                data.version,
                data.revision,
                data.vote_duration,
                data.subject,
                data.body,
                asf_uid,
                asf_uid,
            )
    # except Exception as e:
    #     import traceback
    #     import atr.log as log
    #     log.info(traceback.format_exc())
    #     raise exceptions.BadRequest(str(e))
    except storage.AccessError as e:
        raise exceptions.BadRequest(str(e))

    return models.api.VoteStartResults(
        endpoint="/vote/start",
        task=task,
    ).model_dump(), 201


@api.BLUEPRINT.route("/vote/tabulate", methods=["POST"])
@jwtoken.require
@quart_schema.security_scheme([{"BearerAuth": []}])
@quart_schema.validate_request(models.api.VoteTabulateArgs)
@quart_schema.validate_response(models.api.VoteTabulateResults, 200)
async def vote_tabulate(data: models.api.VoteTabulateArgs) -> DictResponse:
    """
    Tabulate a vote.
    """
    # asf_uid = _jwt_asf_uid()
    async with db.session() as db_data:
        release_name = sql.release_name(data.project, data.version)
        release = await db_data.release(name=release_name, _project_release_policy=True).demand(
            exceptions.NotFound(f"Release {release_name} not found"),
        )

    latest_vote_task = await interaction.release_latest_vote_task(release)
    if latest_vote_task is None:
        raise exceptions.NotFound("No vote task found")
    task_mid = interaction.task_mid_get(latest_vote_task)
    archive_url = await interaction.task_archive_url_cached(task_mid)
    if archive_url is None:
        raise exceptions.NotFound("No archive URL found")
    thread_id = archive_url.split("/")[-1]
    committee = await tabulate.vote_committee(thread_id, release)
    details = await tabulate.vote_details(committee, thread_id, release)
    return models.api.VoteTabulateResults(
        endpoint="/vote/tabulate",
        details=details,
    ).model_dump(), 200


def _committee_member_or_admin(committee: sql.Committee, asf_uid: str) -> None:
    if not (user.is_committee_member(committee, asf_uid) or user.is_admin(asf_uid)):
        raise exceptions.Forbidden("You do not have permission to perform this action")


# @db.session_function
# async def _get_pat(data: db.Session, uid: str, token_hash: str) -> sql.PersonalAccessToken | None:
#     return await data.query_one_or_none(
#         sqlmodel.select(sql.PersonalAccessToken).where(
#             sql.PersonalAccessToken.asfuid == uid,
#             sql.PersonalAccessToken.token_hash == token_hash,
#         )
#     )


def _jwt_asf_uid() -> str:
    claims = getattr(quart.g, "jwt_claims", {})
    asf_uid = claims.get("sub")
    if not isinstance(asf_uid, str):
        raise base.ASFQuartException("Invalid token subject", errorcode=401)
    return asf_uid


async def _match_committee_names(
    key_committees: list[sql.Committee], finished_dir: pathlib.Path, data: models.api.SignatureProvenanceArgs
) -> set[str]:
    key_committee_names = set(committee.name for committee in key_committees)
    finished_dir = util.get_finished_dir()
    matched_committee_names = set()

    # Check for finished files
    for key_committee_name in key_committee_names:
        key_committee_finished_dir = finished_dir / key_committee_name
        async for rel_path in util.paths_recursive(key_committee_finished_dir):
            if rel_path.name == data.signature_file_name:
                abs_path = finished_dir / rel_path
                async with aiofiles.open(abs_path, "rb") as f:
                    rel_path_data = await f.read()
                rel_path_sha3_256 = hashlib.sha3_256(rel_path_data).hexdigest()
                if rel_path_sha3_256 == data.signature_sha3_256:
                    # We got a match
                    matched_committee_names.add(key_committee_name)
                    break

    # Check for unfinished files
    async with db.session() as db_data:
        for key_committee_name in key_committee_names:
            release_directories = []
            projects = await db_data.project(committee_name=key_committee_name).all()
            for project in projects:
                releases = await db_data.release(project_name=project.name).all()
                release_directories.extend(util.release_directory(release) for release in releases)
            for release_directory in release_directories:
                if await _match_unfinished(release_directory, data):
                    matched_committee_names.add(key_committee_name)
                    break
    return matched_committee_names


async def _match_unfinished(release_directory: pathlib.Path, data: models.api.SignatureProvenanceArgs) -> bool:
    async for rel_path in util.paths_recursive(release_directory):
        if rel_path.name == data.signature_file_name:
            abs_path = release_directory / rel_path
            async with aiofiles.open(abs_path, "rb") as f:
                rel_path_data = await f.read()
                rel_path_sha3_256 = hashlib.sha3_256(rel_path_data).hexdigest()
                if rel_path_sha3_256 == data.signature_sha3_256:
                    return True
    return False


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
