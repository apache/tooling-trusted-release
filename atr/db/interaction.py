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
import datetime
import enum
import pathlib
from collections.abc import AsyncGenerator, Sequence
from typing import Any, Final

import aiofiles.os
import aioshutil
import asfquart.base as base
import packaging.version as version
import quart
import sqlalchemy
import sqlmodel

import atr.db as db
import atr.jwtoken as jwtoken
import atr.ldap as ldap
import atr.log as log
import atr.models.results as results
import atr.models.sql as sql
import atr.registry as registry
import atr.user as user
import atr.util as util

# TEST_MID: Final[str | None] = "CAH5JyZo8QnWmg9CwRSwWY=GivhXW4NiLyeNJO71FKdK81J5-Uw@mail.gmail.com"
TEST_MID: Final[str | None] = None
_THREAD_URLS_FOR_DEVELOPMENT: Final[dict[str, str]] = {
    "CAH5JyZo8QnWmg9CwRSwWY=GivhXW4NiLyeNJO71FKdK81J5-Uw@mail.gmail.com": "https://lists.apache.org/thread/z0o7xnjnyw2o886rxvvq2ql4rdfn754w",
    "818a44a3-6984-4aba-a650-834e86780b43@apache.org": "https://lists.apache.org/thread/619hn4x796mh3hkk3kxg1xnl48dy2s64",
    "CAA9ykM+bMPNk=BOF9hj0O+mjN1igppOJ+pKdZHcAM0ddVi+5_w@mail.gmail.com": "https://lists.apache.org/thread/x0m3p2xqjvflgtkb6oxqysm36cr9l5mg",
    "CAFHDsVzgtfboqYF+a3owaNf+55MUiENWd3g53mU4rD=WHkXGwQ@mail.gmail.com": "https://lists.apache.org/thread/brj0k3g8pq63g8f7xhmfg2rbt1240nts",
    "CAMomwMrvKTQK7K2-OtZTrEO0JjXzO2g5ynw3gSoks_PXWPZfoQ@mail.gmail.com": "https://lists.apache.org/thread/y5rqp5qk6dmo08wlc3g20n862hznc9m8",
    "CANVKqzfLYj6TAVP_Sfsy5vFbreyhKskpRY-vs=F7aLed+rL+uA@mail.gmail.com": "https://lists.apache.org/thread/oy969lhh6wlzd51ovckn8fly9rvpopwh",
    "CAH4123ZwGtkwszhEU7qnMByLa-yvyKz2W+DjH_UChPMuzaa54g@mail.gmail.com": "https://lists.apache.org/thread/7111mqyc25sfqxm6bf4ynwhs0bk0r4ys",
    "CADL1oArKFcXvNb1MJfjN=10-yRfKxgpLTRUrdMM1R7ygaTkdYQ@mail.gmail.com": "https://lists.apache.org/thread/d7119h2qm7jrd5zsbp8ghkk0lpvnnxnw",
    "a1507118-88b1-4b7b-923e-7f2b5330fc01@apache.org": "https://lists.apache.org/thread/gzjd2jv7yod5sk5rgdf4x33g5l3fdf5o",
}


class ApacheUserMissingError(RuntimeError):
    def __init__(self, message: str, fingerprint: str | None, primary_uid: str | None) -> None:
        super().__init__(message)
        self.fingerprint = fingerprint
        self.primary_uid = primary_uid


class InteractionError(RuntimeError):
    pass


class PublicKeyError(RuntimeError):
    pass


class ReleasePolicyNotFoundError(RuntimeError):
    pass


class TrustedProjectPhase(enum.Enum):
    COMPOSE = "compose"
    VOTE = "vote"
    FINISH = "finish"


async def all_releases(project: sql.Project) -> list[sql.Release]:
    """Get all releases for the project, sorted by version."""
    query = sqlmodel.select(sql.Release).where(sql.Release.project_name == project.name)

    results = []
    async with db.session() as data:
        for result in (await data.execute(query)).all():
            release = result[0]
            results.append(release)

    for release in results:
        release.project = project

    results.sort(key=lambda r: version.Version(r.version), reverse=True)
    return results


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


async def trusted_jwt(publisher: str, jwt: str, phase: TrustedProjectPhase) -> tuple[dict[str, Any], str, sql.Project]:
    if publisher != "github":
        raise InteractionError(f"Publisher {publisher} not supported")
    payload = await jwtoken.verify_github_oidc(jwt)
    asf_uid = await ldap.github_to_apache(payload["actor_id"])
    project = await _trusted_project(payload["repository"], payload["workflow_ref"], phase)
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


async def promote_release(
    data: db.Session,
    release_name: str,
    selected_revision_number: str,
    vote_manual: bool = False,
) -> str | None:
    """Promote a release candidate draft to a new phase."""
    # TODO: Use session.release here
    release_for_pre_checks = await data.release(name=release_name, _project=True).demand(
        InteractionError("Release candidate draft not found")
    )
    project_name = release_for_pre_checks.project.name
    version_name = release_for_pre_checks.version

    # Check for ongoing tasks
    ongoing_tasks = await tasks_ongoing(project_name, version_name, selected_revision_number)
    if ongoing_tasks > 0:
        return "All checks must be completed before starting a vote"

    # Verify that it's in the correct phase
    # The atomic update below will also check this
    if release_for_pre_checks.phase != sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
        return "This release is not in the candidate draft phase"

    # Check that the revision number is the latest
    if release_for_pre_checks.latest_revision_number != selected_revision_number:
        return "The selected revision number does not match the latest revision number"

    # Check that there is at least one file in the draft
    # This is why we require _project=True above
    file_count = await util.number_of_release_files(release_for_pre_checks)
    if file_count == 0:
        return "This candidate draft is empty, containing no files"

    # Promote it to RELEASE_CANDIDATE
    # NOTE: We previously allowed skipping phases, but removed that functionality
    # We don't need a lock here because we use an atomic update
    via = sql.validate_instrumented_attribute
    stmt = (
        sqlmodel.update(sql.Release)
        .where(
            via(sql.Release.name) == release_name,
            via(sql.Release.phase) == sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
            sql.latest_revision_number_query() == selected_revision_number,
        )
        .values(
            phase=sql.ReleasePhase.RELEASE_CANDIDATE,
            vote_started=datetime.datetime.now(datetime.UTC),
            vote_manual=vote_manual,
        )
    )

    result = await data.execute(stmt)
    if result.rowcount != 1:
        await data.rollback()
        return "A newer revision appeared, please refresh and try again."
    await data.commit()
    return None


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


async def release_latest_vote_task(release: sql.Release) -> sql.Task | None:
    """Find the most recent VOTE_INITIATE task for this release."""
    disallowed_statuses = [sql.TaskStatus.QUEUED, sql.TaskStatus.ACTIVE]
    if util.is_dev_environment():
        disallowed_statuses = []
    via = sql.validate_instrumented_attribute
    async with db.session() as data:
        query = (
            sqlmodel.select(sql.Task)
            .where(sql.Task.project_name == release.project_name)
            .where(sql.Task.version_name == release.version)
            .where(sql.Task.task_type == sql.TaskType.VOTE_INITIATE)
            .where(via(sql.Task.status).notin_(disallowed_statuses))
            .where(via(sql.Task.result).is_not(None))
            .order_by(via(sql.Task.added).desc())
            .limit(1)
        )
        task = (await data.execute(query)).scalar_one_or_none()
        return task


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


async def task_archive_url_cached(task_mid: str | None) -> str | None:
    if task_mid in _THREAD_URLS_FOR_DEVELOPMENT:
        return _THREAD_URLS_FOR_DEVELOPMENT[task_mid]

    if task_mid is None:
        return None
    if "@" not in task_mid:
        return None

    async with db.session() as data:
        url = await data.ns_text_get(
            "mid-url-cache",
            task_mid,
        )
        if url is not None:
            return url

    url = await util.task_archive_url(task_mid)
    if url is not None:
        await data.ns_text_set(
            "mid-url-cache",
            task_mid,
            url,
        )

    return url


def task_mid_get(latest_vote_task: sql.Task) -> str | None:
    if util.is_dev_environment():
        import atr.db.interaction as interaction

        return interaction.TEST_MID
    # TODO: Improve this

    result = latest_vote_task.result
    if not isinstance(result, results.VoteInitiate):
        return None
    return result.mid


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


async def unfinished_releases(asfuid: str) -> list[tuple[str, str, list[sql.Release]]]:
    releases: list[tuple[str, str, list[sql.Release]]] = []
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
                releases.append((project.short_display_name, project.name, active_releases))

    return releases


async def user_committees(asf_uid: str) -> list[tuple[str, str]]:
    results = []
    for committee in await user_committees_participant(asf_uid):
        results.append((committee.name, committee.full_name))
    return results


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


async def user_projects(asf_uid: str, caller_data: db.Session | None = None) -> list[tuple[str, str]]:
    projects = await user.projects(asf_uid)
    return [(p.name, p.display_name) for p in projects]


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


async def _trusted_project(repository: str, workflow_ref: str, phase: TrustedProjectPhase) -> sql.Project:
    # Debugging
    log.info(f"GitHub OIDC JWT payload: {repository} {workflow_ref}")
    repository_name, workflow_path = _trusted_project_checks(repository, workflow_ref)

    rpnf_error = ReleasePolicyNotFoundError(
        f"Release policy for repository {repository_name} and {phase.value} workflow path {workflow_path} not found"
    )
    # TODO: If a policy is reused between projects, we can't get the project
    async with db.session() as db_data:
        match phase:
            case TrustedProjectPhase.COMPOSE:
                # Searches in github_*compose*_workflow_path
                policy = await db_data.release_policy(
                    github_repository_name=repository_name,
                    github_compose_workflow_path_has=workflow_path,
                ).demand(rpnf_error)
            case TrustedProjectPhase.VOTE:
                # Searches in github_*vote*_workflow_path
                policy = await db_data.release_policy(
                    github_repository_name=repository_name,
                    github_vote_workflow_path_has=workflow_path,
                ).demand(rpnf_error)
            case TrustedProjectPhase.FINISH:
                # Searches in github_*finish*_workflow_path
                policy = await db_data.release_policy(
                    github_repository_name=repository_name,
                    github_finish_workflow_path_has=workflow_path,
                ).demand(rpnf_error)
        project = await db_data.project(release_policy_id=policy.id).demand(
            InteractionError(f"Project for release policy {policy.id} not found")
        )
    if project.committee is None:
        raise InteractionError(f"Project {project.name} has no committee")
    if project.committee.name not in registry.GITHUB_AUTOMATED_RELEASE_COMMITTEES:
        raise InteractionError(f"Project {project.name} is not in a committee that can make releases")
    return project


def _trusted_project_checks(repository: str, workflow_ref: str) -> tuple[str, str]:
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
    return repository_name, workflow_path
