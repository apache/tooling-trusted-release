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

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any, Final, Generic, TypeGuard, TypeVar

import sqlalchemy
import sqlalchemy.dialects.sqlite
import sqlalchemy.ext.asyncio
import sqlalchemy.orm as orm
import sqlalchemy.sql as sql
import sqlmodel
import sqlmodel.sql.expression as expression

import atr.config as config
import atr.db.models as models
import atr.util as util

if TYPE_CHECKING:
    import datetime
    from collections.abc import Sequence

    import asfquart.base as base

_LOGGER: Final = logging.getLogger(__name__)

_global_atr_engine: sqlalchemy.ext.asyncio.AsyncEngine | None = None
_global_atr_sessionmaker: sqlalchemy.ext.asyncio.async_sessionmaker | None = None


T = TypeVar("T")


class NotSet:
    """
    A marker class to indicate that a value is not set and thus should
    not be considered. This is different to None.
    """

    _instance = None

    def __new__(cls):  # type: ignore
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "<NotSet>"

    def __copy__(self):  # type: ignore
        return NotSet

    def __deepcopy__(self, memo: dict[int, Any]):  # type: ignore
        return NotSet


_NOT_SET: Final[NotSet] = NotSet()
type Opt[T] = T | NotSet


class Query(Generic[T]):
    def __init__(self, session: Session, query: expression.SelectOfScalar[T]):
        self.query = query
        self.session = session

    def order_by(self, *args: Any, **kwargs: Any) -> Query[T]:
        self.query = self.query.order_by(*args, **kwargs)
        return self

    async def get(self) -> T | None:
        result = await self.session.execute(self.query)
        return result.scalar_one_or_none()

    async def demand(self, error: Exception) -> T:
        result = await self.session.execute(self.query)
        item = result.scalar_one_or_none()
        if item is None:
            raise error
        return item

    async def all(self) -> Sequence[T]:
        result = await self.session.execute(self.query)
        return result.scalars().all()

    # async def execute(self) -> sqlalchemy.Result[tuple[T]]:
    #     return await self.session.execute(self.query)


class Session(sqlalchemy.ext.asyncio.AsyncSession):
    # TODO: Need to type all of these arguments correctly

    def check_result(
        self,
        id: Opt[int] = _NOT_SET,
        release_name: Opt[str] = _NOT_SET,
        checker: Opt[str] = _NOT_SET,
        primary_rel_path: Opt[str | None] = _NOT_SET,
        created: Opt[datetime.datetime] = _NOT_SET,
        status: Opt[models.CheckResultStatus] = _NOT_SET,
        message: Opt[str] = _NOT_SET,
        data: Opt[Any] = _NOT_SET,
        _release: bool = False,
    ) -> Query[models.CheckResult]:
        query = sqlmodel.select(models.CheckResult)

        if is_defined(id):
            query = query.where(models.CheckResult.id == id)
        if is_defined(release_name):
            query = query.where(models.CheckResult.release_name == release_name)
        if is_defined(checker):
            query = query.where(models.CheckResult.checker == checker)
        if is_defined(primary_rel_path):
            query = query.where(models.CheckResult.primary_rel_path == primary_rel_path)
        if is_defined(created):
            query = query.where(models.CheckResult.created == created)
        if is_defined(status):
            query = query.where(models.CheckResult.status == status)
        if is_defined(message):
            query = query.where(models.CheckResult.message == message)
        if is_defined(data):
            query = query.where(models.CheckResult.data == data)

        if _release:
            query = query.options(select_in_load(models.CheckResult.release))

        return Query(self, query)

    def committee(
        self,
        id: Opt[int] = _NOT_SET,
        name: Opt[str] = _NOT_SET,
        full_name: Opt[str] = _NOT_SET,
        is_podling: Opt[bool] = _NOT_SET,
        parent_committee_id: Opt[int] = _NOT_SET,
        committee_members: Opt[list[str]] = _NOT_SET,
        committers: Opt[list[str]] = _NOT_SET,
        release_managers: Opt[list[str]] = _NOT_SET,
        vote_policy_id: Opt[int] = _NOT_SET,
        name_in: Opt[list[str]] = _NOT_SET,
        _projects: bool = False,
        _public_signing_keys: bool = False,
    ) -> Query[models.Committee]:
        query = sqlmodel.select(models.Committee)

        if is_defined(id):
            query = query.where(models.Committee.id == id)
        if is_defined(name):
            query = query.where(models.Committee.name == name)
        if is_defined(full_name):
            query = query.where(models.Committee.full_name == full_name)
        if is_defined(is_podling):
            query = query.where(models.Committee.is_podling == is_podling)
        if is_defined(parent_committee_id):
            query = query.where(models.Committee.parent_committee_id == parent_committee_id)
        if is_defined(committee_members):
            query = query.where(models.Committee.committee_members == committee_members)
        if is_defined(committers):
            query = query.where(models.Committee.committers == committers)
        if is_defined(release_managers):
            query = query.where(models.Committee.release_managers == release_managers)

        if is_defined(name_in):
            models_committee_name = validate_instrumented_attribute(models.Committee.name)
            query = query.where(models_committee_name.in_(name_in))

        if _projects:
            query = query.options(select_in_load(models.Committee.projects))
        if _public_signing_keys:
            query = query.options(select_in_load(models.Committee.public_signing_keys))

        return Query(self, query)

    async def ns_text_del(self, ns: str, key: str, commit: bool = True) -> None:
        stmt = sql.delete(models.TextValue).where(
            validate_instrumented_attribute(models.TextValue.ns) == ns,
            validate_instrumented_attribute(models.TextValue.key) == key,
        )
        await self.execute(stmt)
        if commit is True:
            await self.commit()

    async def ns_text_get(self, ns: str, key: str) -> str | None:
        stmt = sql.select(models.TextValue).where(
            validate_instrumented_attribute(models.TextValue.ns) == ns,
            validate_instrumented_attribute(models.TextValue.key) == key,
        )
        result = await self.execute(stmt)
        match result.scalar_one_or_none():
            case models.TextValue(value=value):
                return value
            case None:
                return None

    async def ns_text_set(self, ns: str, key: str, value: str, commit: bool = True) -> None:
        # Don't use sql.insert(), it won't give on_conflict_do_update()
        stmt = sqlalchemy.dialects.sqlite.insert(models.TextValue).values((ns, key, value))
        stmt = stmt.on_conflict_do_update(
            index_elements=[models.TextValue.ns, models.TextValue.key], set_=dict(value=value)
        )
        await self.execute(stmt)
        if commit is True:
            await self.commit()

    def package(
        self,
        artifact_sha3: Opt[str] = _NOT_SET,
        artifact_type: Opt[str] = _NOT_SET,
        filename: Opt[str] = _NOT_SET,
        sha512: Opt[str] = _NOT_SET,
        signature_sha3: Opt[str | None] = _NOT_SET,
        uploaded: Opt[datetime.datetime] = _NOT_SET,
        bytes_size: Opt[int] = _NOT_SET,
        release_name: Opt[str] = _NOT_SET,
        _release: bool = False,
        _release_project: bool = False,
        _release_committee: bool = False,
    ) -> Query[models.Package]:
        query = sqlmodel.select(models.Package)

        if is_defined(artifact_sha3):
            query = query.where(models.Package.artifact_sha3 == artifact_sha3)
        if is_defined(artifact_type):
            query = query.where(models.Package.artifact_type == artifact_type)
        if is_defined(filename):
            query = query.where(models.Package.filename == filename)
        if is_defined(sha512):
            query = query.where(models.Package.sha512 == sha512)
        if is_defined(signature_sha3):
            query = query.where(models.Package.signature_sha3 == signature_sha3)
        if is_defined(uploaded):
            query = query.where(models.Package.uploaded == uploaded)
        if is_defined(bytes_size):
            query = query.where(models.Package.bytes_size == bytes_size)
        if is_defined(release_name):
            query = query.where(models.Package.release_name == release_name)

        if _release:
            query = query.options(select_in_load(models.Package.release))
        if _release_project:
            query = query.options(select_in_load_nested(models.Package.release, models.Release.project))
        if _release_committee:
            query = query.options(
                select_in_load_nested(models.Package.release, models.Release.project, models.Project.committee)
            )

        return Query(self, query)

    def project(
        self,
        id: Opt[int] = _NOT_SET,
        name: Opt[str] = _NOT_SET,
        full_name: Opt[str] = _NOT_SET,
        is_podling: Opt[bool] = _NOT_SET,
        committee_id: Opt[int] = _NOT_SET,
        vote_policy_id: Opt[int] = _NOT_SET,
        _committee: bool = False,
        _releases: bool = False,
        _distribution_channels: bool = False,
        _vote_policy: bool = False,
        _committee_public_signing_keys: bool = False,
    ) -> Query[models.Project]:
        query = sqlmodel.select(models.Project)

        if is_defined(id):
            query = query.where(models.Project.id == id)
        if is_defined(name):
            query = query.where(models.Project.name == name)
        if is_defined(full_name):
            query = query.where(models.Project.full_name == full_name)
        if is_defined(is_podling):
            query = query.where(models.Project.is_podling == is_podling)
        if is_defined(committee_id):
            query = query.where(models.Project.committee_id == committee_id)
        if is_defined(vote_policy_id):
            query = query.where(models.Project.vote_policy_id == vote_policy_id)

        if _committee:
            query = query.options(select_in_load(models.Project.committee))
        if _releases:
            query = query.options(select_in_load(models.Project.releases))
        if _distribution_channels:
            query = query.options(select_in_load(models.Project.distribution_channels))
        if _vote_policy:
            query = query.options(select_in_load(models.Project.vote_policy))
        if _committee_public_signing_keys:
            query = query.options(select_in_load_nested(models.Project.committee, models.Committee.public_signing_keys))

        return Query(self, query)

    def public_signing_key(
        self,
        fingerprint: Opt[str] = _NOT_SET,
        algorithm: Opt[str] = _NOT_SET,
        length: Opt[int] = _NOT_SET,
        created: Opt[datetime.datetime] = _NOT_SET,
        expires: Opt[datetime.datetime | None] = _NOT_SET,
        declared_uid: Opt[str | None] = _NOT_SET,
        apache_uid: Opt[str] = _NOT_SET,
        ascii_armored_key: Opt[str] = _NOT_SET,
        _committees: bool = False,
    ) -> Query[models.PublicSigningKey]:
        query = sqlmodel.select(models.PublicSigningKey)

        if is_defined(fingerprint):
            query = query.where(models.PublicSigningKey.fingerprint == fingerprint)
        if is_defined(algorithm):
            query = query.where(models.PublicSigningKey.algorithm == algorithm)
        if is_defined(length):
            query = query.where(models.PublicSigningKey.length == length)
        if is_defined(created):
            query = query.where(models.PublicSigningKey.created == created)
        if is_defined(expires):
            query = query.where(models.PublicSigningKey.expires == expires)
        if is_defined(declared_uid):
            query = query.where(models.PublicSigningKey.declared_uid == declared_uid)
        if is_defined(apache_uid):
            query = query.where(models.PublicSigningKey.apache_uid == apache_uid)
        if is_defined(ascii_armored_key):
            query = query.where(models.PublicSigningKey.ascii_armored_key == ascii_armored_key)

        if _committees:
            query = query.options(select_in_load(models.PublicSigningKey.committees))

        return Query(self, query)

    def release(
        self,
        name: Opt[str] = _NOT_SET,
        stage: Opt[models.ReleaseStage] = _NOT_SET,
        phase: Opt[models.ReleasePhase] = _NOT_SET,
        created: Opt[datetime.datetime] = _NOT_SET,
        project_id: Opt[int] = _NOT_SET,
        package_managers: Opt[list[str]] = _NOT_SET,
        version: Opt[str] = _NOT_SET,
        sboms: Opt[list[str]] = _NOT_SET,
        vote_policy_id: Opt[int] = _NOT_SET,
        votes: Opt[list[models.VoteEntry]] = _NOT_SET,
        _project: bool = False,
        _packages: bool = False,
        _vote_policy: bool = False,
        _committee: bool = False,
        _tasks: bool = False,
    ) -> Query[models.Release]:
        query = sqlmodel.select(models.Release)

        if is_defined(name):
            query = query.where(models.Release.name == name)
        if is_defined(stage):
            query = query.where(models.Release.stage == stage)
        if is_defined(phase):
            query = query.where(models.Release.phase == phase)
        if is_defined(created):
            query = query.where(models.Release.created == created)
        if is_defined(project_id):
            query = query.where(models.Release.project_id == project_id)
        if is_defined(package_managers):
            query = query.where(models.Release.package_managers == package_managers)
        if is_defined(version):
            query = query.where(models.Release.version == version)
        if is_defined(sboms):
            query = query.where(models.Release.sboms == sboms)
        if is_defined(vote_policy_id):
            query = query.where(models.Release.vote_policy_id == vote_policy_id)
        if is_defined(votes):
            query = query.where(models.Release.votes == votes)

        if _project:
            query = query.options(select_in_load(models.Release.project))
        if _packages:
            query = query.options(select_in_load(models.Release.packages))
        if _vote_policy:
            query = query.options(select_in_load(models.Release.vote_policy))
        if _committee:
            query = query.options(select_in_load_nested(models.Release.project, models.Project.committee))
        if _tasks:
            query = query.options(select_in_load(models.Release.tasks))

        return Query(self, query)

    def ssh_key(
        self,
        fingerprint: Opt[str] = _NOT_SET,
        key: Opt[str] = _NOT_SET,
        asf_uid: Opt[str] = _NOT_SET,
    ) -> Query[models.SSHKey]:
        query = sqlmodel.select(models.SSHKey)

        if is_defined(fingerprint):
            query = query.where(models.SSHKey.fingerprint == fingerprint)
        if is_defined(key):
            query = query.where(models.SSHKey.key == key)
        if is_defined(asf_uid):
            query = query.where(models.SSHKey.asf_uid == asf_uid)

        return Query(self, query)

    def task(
        self,
        id: Opt[int] = _NOT_SET,
        status: Opt[models.TaskStatus] = _NOT_SET,
        task_type: Opt[str] = _NOT_SET,
        task_args: Opt[Any] = _NOT_SET,
        added: Opt[datetime.datetime] = _NOT_SET,
        started: Opt[datetime.datetime | None] = _NOT_SET,
        pid: Opt[int | None] = _NOT_SET,
        completed: Opt[datetime.datetime | None] = _NOT_SET,
        result: Opt[Any | None] = _NOT_SET,
        error: Opt[str | None] = _NOT_SET,
        release_name: Opt[str | None] = _NOT_SET,
        path: Opt[str | None] = _NOT_SET,
        modified: Opt[int | None] = _NOT_SET,
        _release: bool = False,
    ) -> Query[models.Task]:
        query = sqlmodel.select(models.Task)

        if is_defined(id):
            query = query.where(models.Task.id == id)
        if is_defined(status):
            query = query.where(models.Task.status == status)
        if is_defined(task_type):
            query = query.where(models.Task.task_type == task_type)
        if is_defined(task_args):
            query = query.where(models.Task.task_args == task_args)
        if is_defined(added):
            query = query.where(models.Task.added == added)
        if is_defined(started):
            query = query.where(models.Task.started == started)
        if is_defined(pid):
            query = query.where(models.Task.pid == pid)
        if is_defined(completed):
            query = query.where(models.Task.completed == completed)
        if is_defined(result):
            query = query.where(models.Task.result == result)
        if is_defined(error):
            query = query.where(models.Task.error == error)
        if is_defined(release_name):
            query = query.where(models.Task.release_name == release_name)

        if _release:
            query = query.options(select_in_load(models.Task.release))

        return Query(self, query)

    def vote_policy(
        self,
        id: Opt[int] = _NOT_SET,
        mailto_addresses: Opt[list[str]] = _NOT_SET,
        manual_vote: Opt[bool] = _NOT_SET,
        min_hours: Opt[int] = _NOT_SET,
        release_checklist: Opt[str] = _NOT_SET,
        pause_for_rm: Opt[bool] = _NOT_SET,
        _project: bool = False,
    ) -> Query[models.VotePolicy]:
        query = sqlmodel.select(models.VotePolicy)

        if is_defined(id):
            query = query.where(models.VotePolicy.id == id)
        if is_defined(mailto_addresses):
            query = query.where(models.VotePolicy.mailto_addresses == mailto_addresses)
        if is_defined(manual_vote):
            query = query.where(models.VotePolicy.manual_vote == manual_vote)
        if is_defined(min_hours):
            query = query.where(models.VotePolicy.min_hours == min_hours)
        if is_defined(release_checklist):
            query = query.where(models.VotePolicy.release_checklist == release_checklist)
        if is_defined(pause_for_rm):
            query = query.where(models.VotePolicy.pause_for_rm == pause_for_rm)

        if _project:
            query = query.options(select_in_load(models.VotePolicy.project))

        return Query(self, query)

    def text_value(
        self,
        ns: Opt[str] = _NOT_SET,
        key: Opt[str] = _NOT_SET,
        value: Opt[str] = _NOT_SET,
    ) -> Query[models.TextValue]:
        query = sqlmodel.select(models.TextValue)

        if is_defined(ns):
            query = query.where(models.TextValue.ns == ns)
        if is_defined(key):
            query = query.where(models.TextValue.key == key)
        if is_defined(value):
            query = query.where(models.TextValue.value == value)

        return Query(self, query)


async def create_async_engine(app_config: type[config.AppConfig]) -> sqlalchemy.ext.asyncio.AsyncEngine:
    sqlite_url = f"sqlite+aiosqlite://{app_config.SQLITE_DB_PATH}"
    # Use aiosqlite for async SQLite access
    engine = sqlalchemy.ext.asyncio.create_async_engine(
        sqlite_url,
        connect_args={
            "check_same_thread": False,
            "timeout": 30,
        },
    )

    # Set SQLite pragmas for better performance
    # Use 64 MB for the cache_size, and 5000ms for busy_timeout
    async with engine.begin() as conn:
        await conn.execute(sql.text("PRAGMA journal_mode=WAL"))
        await conn.execute(sql.text("PRAGMA synchronous=NORMAL"))
        await conn.execute(sql.text("PRAGMA cache_size=-64000"))
        await conn.execute(sql.text("PRAGMA foreign_keys=ON"))
        await conn.execute(sql.text("PRAGMA busy_timeout=5000"))

    return engine


def init_database(app: base.QuartApp) -> None:
    """
    Creates and initializes the database for a QuartApp.

    The database is created and an AsyncSession is registered as extension for the app.
    Any pending migrations are executed.
    """

    @app.before_serving
    async def create() -> None:
        global _global_atr_engine, _global_atr_sessionmaker

        app_config = config.get()
        engine = await create_async_engine(app_config)
        _global_atr_engine = engine

        _global_atr_sessionmaker = sqlalchemy.ext.asyncio.async_sessionmaker(
            bind=engine, class_=Session, expire_on_commit=False
        )

        # Run any pending migrations
        # In dev we'd do this first:
        # poetry run alembic revision --autogenerate -m "description"
        # Then review the generated migration in migrations/versions/ and commit it
        # project_root = app_config.PROJECT_ROOT
        # alembic_ini_path = os.path.join(project_root, "alembic.ini")
        # alembic_cfg = config.Config(alembic_ini_path)
        # # Override the migrations directory location to use project root
        # # TODO: Is it possible to set this in alembic.ini?
        # alembic_cfg.set_main_option("script_location", os.path.join(project_root, "migrations"))
        # # Set the database URL in the config
        # alembic_cfg.set_main_option("sqlalchemy.url", str(engine.url))
        # # command.upgrade(alembic_cfg, "head")

        # Create any tables that might be missing
        async with engine.begin() as conn:
            await conn.run_sync(sqlmodel.SQLModel.metadata.create_all)


async def init_database_for_worker() -> None:
    global _global_atr_engine, _global_atr_sessionmaker

    _LOGGER.info(f"Creating database for worker {os.getpid()}")
    engine = await create_async_engine(config.get())
    _global_atr_engine = engine
    _global_atr_sessionmaker = sqlalchemy.ext.asyncio.async_sessionmaker(
        bind=engine, class_=Session, expire_on_commit=False
    )


def is_defined(v: T | NotSet) -> TypeGuard[T]:
    return not isinstance(v, NotSet)


def is_undefined(v: T | NotSet) -> TypeGuard[NotSet]:
    return isinstance(v, NotSet)


# async def recent_tasks(data: Session, release_name: str, file_path: str, modified: int) -> dict[str, models.Task]:
#     """Get the most recent task for each task type for a specific file."""
#     tasks = await data.task(
#         release_name=release_name,
#         path=str(file_path),
#         modified=modified,
#     ).all()
#
#     # Group by task_type and keep the most recent one
#     # We use the highest id to determine the most recent task
#     recent_tasks: dict[str, models.Task] = {}
#     for task in tasks:
#         # If we haven't seen this task type before or if this task is newer
#         if (task.task_type.value not in recent_tasks) or (task.id > recent_tasks[task.task_type.value].id):
#             recent_tasks[task.task_type.value] = task
#
#     return recent_tasks


def select_in_load(*entities: Any) -> orm.strategy_options._AbstractLoad:
    """Eagerly load the given entities from the query."""
    validated_entities = []
    for entity in entities:
        if not isinstance(entity, orm.InstrumentedAttribute):
            raise ValueError(f"Object must be an orm.InstrumentedAttribute, got: {type(entity)}")
        validated_entities.append(entity)
    return orm.selectinload(*validated_entities)


def select_in_load_nested(parent: Any, *descendants: Any) -> orm.strategy_options._AbstractLoad:
    """Eagerly load the given nested entities from the query."""
    if not isinstance(parent, orm.InstrumentedAttribute):
        raise ValueError(f"Parent must be an orm.InstrumentedAttribute, got: {type(parent)}")
    for descendant in descendants:
        if not isinstance(descendant, orm.InstrumentedAttribute):
            raise ValueError(f"Descendant must be an orm.InstrumentedAttribute, got: {type(descendant)}")
    result = orm.selectinload(parent)
    for descendant in descendants:
        result = result.selectinload(descendant)
    return result


def session() -> Session:
    """Create a new asynchronous database session."""

    # FIXME: occasionally you see this in the console output
    # <sys>:0: SAWarning: The garbage collector is trying to clean up non-checked-in connection <AdaptedConnection
    # <Connection(Thread-291, started daemon 138838634661440)>>, which will be dropped, as it cannot be safely
    # terminated. Please ensure that SQLAlchemy pooled connections are returned to the pool explicitly, either by
    # calling ``close()`` or by using appropriate context managers to manage their lifecycle.

    # Not fully clear where this is coming from, but we could experiment by returning a session like that:
    # async def session() -> AsyncGenerator[Session, None]:
    #     async with _global_atr_sessionmaker() as session:
    #         yield session

    # from FastAPI documentation: https://fastapi-users.github.io/fastapi-users/latest/configuration/databases/sqlalchemy/

    if _global_atr_sessionmaker is None:
        raise RuntimeError("database not initialized")
    else:
        return util.validate_as_type(_global_atr_sessionmaker(), Session)


async def shutdown_database() -> None:
    if _global_atr_engine:
        _LOGGER.info("Closing database")
        await _global_atr_engine.dispose()
    else:
        _LOGGER.info("No database to close")


async def tasks_ongoing(project_name: str, version_name: str, draft_revision: str) -> int:
    release_name = models.release_name(project_name, version_name)
    async with session() as data:
        query = (
            sqlmodel.select(sqlalchemy.func.count())
            .select_from(models.Task)
            .where(
                models.Task.release_name == release_name,
                models.Task.draft_revision == draft_revision,
                validate_instrumented_attribute(models.Task.status).in_(
                    [models.TaskStatus.QUEUED, models.TaskStatus.ACTIVE]
                ),
            )
        )
        result = await data.execute(query)
        return result.scalar_one()


def validate_instrumented_attribute(obj: Any) -> orm.InstrumentedAttribute:
    """Check if the given object is an InstrumentedAttribute."""
    if not isinstance(obj, orm.InstrumentedAttribute):
        raise ValueError(f"Object must be an orm.InstrumentedAttribute, got: {type(obj)}")
    return obj
