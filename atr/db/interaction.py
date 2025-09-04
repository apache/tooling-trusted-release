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

import contextlib
import pathlib
from collections.abc import AsyncGenerator, Sequence
from typing import Any

import aiofiles.os
import aioshutil
import asfquart.base as base
import quart
import sqlalchemy
import sqlmodel

import atr.db as db
import atr.jwtoken as jwtoken
import atr.ldap as ldap
import atr.log as log
import atr.models.sql as sql
import atr.registry as registry
import atr.user as user
import atr.util as util


class ApacheUserMissingError(RuntimeError):
    def __init__(self, message: str, fingerprint: str | None, primary_uid: str | None) -> None:
        super().__init__(message)
        self.fingerprint = fingerprint
        self.primary_uid = primary_uid


class InteractionError(RuntimeError):
    pass


class PublicKeyError(RuntimeError):
    pass


async def candidate_drafts(project: sql.Project) -> list[sql.Release]:
    """Get the candidate drafts for the project."""
    return await releases_by_phase(project, sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT)


async def candidates(project: sql.Project) -> list[sql.Release]:
    """Get the candidate releases for the project."""
    return await releases_by_phase(project, sql.ReleasePhase.RELEASE_CANDIDATE)


@contextlib.asynccontextmanager
async def ephemeral_gpg_home() -> AsyncGenerator[str]:
    """Create a temporary directory for an isolated GPG home, and clean it up on exit."""
    async with util.async_temporary_directory(prefix="gpg-") as temp_dir:
        yield str(temp_dir)


async def full_releases(project: sql.Project) -> list[sql.Release]:
    """Get the full releases for the project."""
    return await releases_by_phase(project, sql.ReleasePhase.RELEASE)


async def github_trusted_jwt(jwt: str) -> tuple[dict[str, Any], str, sql.Project]:
    payload = await jwtoken.verify_github_oidc(jwt)
    asf_uid = await ldap.github_to_apache(payload["actor_id"])
    project = await _trusted_project(payload["repository"], payload["workflow_ref"])
    return payload, asf_uid, project


async def has_failing_checks(release: sql.Release, revision_number: str, caller_data: db.Session | None = None) -> bool:
    async with db.ensure_session(caller_data) as data:
        query = (
            sqlmodel.select(sqlalchemy.func.count())
            .select_from(sql.CheckResult)
            .where(
                sql.CheckResult.release_name == release.name,
                sql.CheckResult.revision_number == revision_number,
                sql.CheckResult.status == sql.CheckResultStatus.FAILURE,
            )
        )
        result = await data.execute(query)
        return result.scalar_one() > 0


async def latest_revision(release: sql.Release) -> sql.Revision | None:
    if release.latest_revision_number is None:
        return None
    async with db.session() as data:
        return await data.revision(release_name=release.name, number=release.latest_revision_number).get()


async def previews(project: sql.Project) -> list[sql.Release]:
    """Get the preview releases for the project."""
    return await releases_by_phase(project, sql.ReleasePhase.RELEASE_PREVIEW)


async def release_delete(
    release_name: str, phase: db.Opt[sql.ReleasePhase] = db.NOT_SET, include_downloads: bool = True
) -> None:
    """Handle the deletion of database records and filesystem data for a release."""
    async with db.session() as data:
        release = await data.release(name=release_name, phase=phase, _project=True).demand(
            base.ASFQuartException(f"Release '{release_name}' not found.", 404)
        )
        release_dir = util.release_directory_base(release)

        # Delete from the database
        log.info("Deleting database records for release: %s", release_name)
        # Cascade should handle this, but we delete manually anyway
        tasks_to_delete = await data.task(project_name=release.project.name, version_name=release.version).all()
        for task in tasks_to_delete:
            await data.delete(task)
        log.debug("Deleted %d tasks for %s", len(tasks_to_delete), release_name)

        checks_to_delete = await data.check_result(release_name=release_name).all()
        for check in checks_to_delete:
            await data.delete(check)
        log.debug("Deleted %d check results for %s", len(checks_to_delete), release_name)

        # TODO: Ensure that revisions are not deleted
        # But this makes testing difficult
        # Perhaps delete revisions if associated with test accounts only
        # But we want to test actual mechanisms, not special case tests
        # We could create uniquely named releases in tests
        # Currently part of the discussion in #171, but should be its own issue
        await data.delete(release)
        log.info("Deleted release record: %s", release_name)
        await data.commit()

    if include_downloads:
        await _delete_release_data_downloads(release)
    await _delete_release_data_filesystem(release_dir, release_name)


async def releases_by_phase(project: sql.Project, phase: sql.ReleasePhase) -> list[sql.Release]:
    """Get the releases for the project by phase."""

    query = (
        sqlmodel.select(sql.Release)
        .where(
            sql.Release.project_name == project.name,
            sql.Release.phase == phase,
        )
        .order_by(sql.validate_instrumented_attribute(sql.Release.created).desc())
    )

    results = []
    async with db.session() as data:
        for result in (await data.execute(query)).all():
            release = result[0]
            results.append(release)

    for release in results:
        # Don't need to eager load and lose it when the session closes
        release.project = project
    return results


async def releases_in_progress(project: sql.Project) -> list[sql.Release]:
    """Get the releases in progress for the project."""
    drafts = await candidate_drafts(project)
    cands = await candidates(project)
    prevs = await previews(project)
    return drafts + cands + prevs


async def tasks_ongoing(project_name: str, version_name: str, revision_number: str | None = None) -> int:
    tasks = sqlmodel.select(sqlalchemy.func.count()).select_from(sql.Task)
    async with db.session() as data:
        query = tasks.where(
            sql.Task.project_name == project_name,
            sql.Task.version_name == version_name,
            sql.Task.revision_number
            == (sql.RELEASE_LATEST_REVISION_NUMBER if (revision_number is None) else revision_number),
            sql.validate_instrumented_attribute(sql.Task.status).in_([sql.TaskStatus.QUEUED, sql.TaskStatus.ACTIVE]),
        )
        result = await data.execute(query)
        return result.scalar_one()


async def tasks_ongoing_revision(
    project_name: str,
    version_name: str,
    revision_number: str | None = None,
) -> tuple[int, str]:
    via = sql.validate_instrumented_attribute
    subquery = (
        sqlalchemy.select(via(sql.Revision.number))
        .where(
            via(sql.Revision.release_name) == sql.release_name(project_name, version_name),
        )
        .order_by(via(sql.Revision.seq).desc())
        .limit(1)
        .scalar_subquery()
        .label("latest_revision")
    )

    query = (
        sqlmodel.select(
            sqlalchemy.func.count().label("task_count"),
            subquery,
        )
        .select_from(sql.Task)
        .where(
            sql.Task.project_name == project_name,
            sql.Task.version_name == version_name,
            sql.Task.revision_number == (subquery if revision_number is None else revision_number),
            sql.validate_instrumented_attribute(sql.Task.status).in_(
                [sql.TaskStatus.QUEUED, sql.TaskStatus.ACTIVE],
            ),
        )
    )

    async with db.session() as session:
        task_count, latest_revision = (await session.execute(query)).one()
        return task_count, latest_revision


async def unfinished_releases(asfuid: str) -> dict[str, list[sql.Release]]:
    releases: dict[str, list[sql.Release]] = {}
    async with db.session() as data:
        user_projects = await user.projects(asfuid)
        user_projects.sort(key=lambda p: p.display_name)

        active_phases = [
            sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
            sql.ReleasePhase.RELEASE_CANDIDATE,
            sql.ReleasePhase.RELEASE_PREVIEW,
        ]
        for project in user_projects:
            stmt = (
                sqlmodel.select(sql.Release)
                .where(
                    sql.Release.project_name == project.name,
                    sql.validate_instrumented_attribute(sql.Release.phase).in_(active_phases),
                )
                .options(db.select_in_load(sql.Release.project))
                .order_by(sql.validate_instrumented_attribute(sql.Release.created).desc())
            )
            result = await data.execute(stmt)
            active_releases = list(result.scalars().all())
            if active_releases:
                active_releases.sort(key=lambda r: r.created, reverse=True)
                releases[project.short_display_name] = active_releases

    return releases


# This function cannot go in user.py because it causes a circular import
async def user_committees_committer(asf_uid: str, caller_data: db.Session | None = None) -> Sequence[sql.Committee]:
    async with db.ensure_session(caller_data) as data:
        return await data.committee(has_committer=asf_uid).all()


# This function cannot go in user.py because it causes a circular import
async def user_committees_member(asf_uid: str, caller_data: db.Session | None = None) -> Sequence[sql.Committee]:
    async with db.ensure_session(caller_data) as data:
        return await data.committee(has_member=asf_uid).all()


# This function cannot go in user.py because it causes a circular import
async def user_committees_participant(asf_uid: str, caller_data: db.Session | None = None) -> Sequence[sql.Committee]:
    async with db.ensure_session(caller_data) as data:
        return await data.committee(has_participant=asf_uid).all()


async def _delete_release_data_downloads(release: sql.Release) -> None:
    # Delete hard links from the downloads directory
    finished_dir = util.release_directory(release)
    if await aiofiles.os.path.isdir(finished_dir):
        release_inodes = set()
        async for file_path in util.paths_recursive(finished_dir):
            try:
                stat_result = await aiofiles.os.stat(finished_dir / file_path)
                release_inodes.add(stat_result.st_ino)
            except FileNotFoundError:
                continue

        if release_inodes:
            downloads_dir = util.get_downloads_dir()
            async for link_path in util.paths_recursive(downloads_dir):
                full_link_path = downloads_dir / link_path
                try:
                    link_stat = await aiofiles.os.stat(full_link_path)
                    if link_stat.st_ino in release_inodes:
                        await aiofiles.os.remove(full_link_path)
                        log.info(f"Deleted hard link: {full_link_path}")
                except FileNotFoundError:
                    continue


async def _delete_release_data_filesystem(release_dir: pathlib.Path, release_name: str) -> None:
    # Delete from the filesystem
    try:
        if await aiofiles.os.path.isdir(release_dir):
            log.info("Deleting filesystem directory: %s", release_dir)
            # Believe this to be another bug in mypy Protocol handling
            # TODO: Confirm that this is a bug, and report upstream
            await aioshutil.rmtree(release_dir)  # type: ignore[call-arg]
            log.info("Successfully deleted directory: %s", release_dir)
        else:
            log.warning("Filesystem directory not found, skipping deletion: %s", release_dir)
    except Exception as e:
        log.exception("Error deleting filesystem directory %s:", release_dir)
        await quart.flash(
            f"Database records for '{release_name}' deleted, but failed to delete filesystem directory: {e!s}",
            "warning",
        )


async def _trusted_project(repository: str, workflow_ref: str) -> sql.Project:
    # Debugging
    log.info(f"GitHub OIDC JWT payload: {repository} {workflow_ref}")

    if not repository.startswith("apache/"):
        raise InteractionError("Repository must start with 'apache/'")
    repository_name = repository.removeprefix("apache/")
    if not workflow_ref.startswith(repository + "/"):
        raise InteractionError(f"Workflow ref must start with repository, got {workflow_ref}")
    workflow_path_at = workflow_ref.removeprefix(repository + "/")
    if "@" not in workflow_path_at:
        raise InteractionError(f"Workflow path must contain '@', got {workflow_path_at}")
    workflow_path = workflow_path_at.rsplit("@", 1)[0]
    if not workflow_path.startswith(".github/workflows/"):
        raise InteractionError(f"Workflow path must start with '.github/workflows/', got {workflow_path}")
    # TODO: If a policy is reused between projects, we can't get the project
    async with db.session() as db_data:
        policy = await db_data.release_policy(
            github_repository_name=repository_name, github_workflow_path=workflow_path
        ).demand(
            InteractionError(
                f"No release policy found for repository name {repository_name} and workflow path {workflow_path}"
            )
        )
        project = await db_data.project(release_policy_id=policy.id).demand(
            InteractionError(f"Project for release policy {policy.id} not found")
        )
    if project.committee is None:
        raise InteractionError(f"Project {project.name} has no committee")
    if project.committee.name not in registry.GITHUB_AUTOMATED_RELEASE_COMMITTEES:
        raise InteractionError(f"Project {project.name} is not in a committee that can make releases")
    log.info(f"Release policy: {policy}")
    log.info(f"Project: {project}")
    return project
