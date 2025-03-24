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

import quart
import sqlalchemy
import sqlalchemy.ext.asyncio
import sqlalchemy.orm as orm
import sqlalchemy.sql as sql
import sqlmodel
import sqlmodel.sql.expression as expression

import atr.config as config
import atr.db.models as models
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    import asfquart.base as base

    from atr.db.models import ReleasePhase, ReleaseStage, TaskStatus, VoteEntry

_LOGGER: Final = logging.getLogger(__name__)

_global_async_sessionmaker: sqlalchemy.ext.asyncio.async_sessionmaker | None = None
_global_atr_sessionmaker: sqlalchemy.ext.asyncio.async_sessionmaker | None = None
_global_sync_engine: sqlalchemy.Engine | None = None


T = TypeVar("T")


class _NotSetType:
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


NotSet = _NotSetType()
type Opt[T] = T | _NotSetType


def is_defined(v: T | _NotSetType) -> TypeGuard[T]:
    return not isinstance(v, _NotSetType)


def is_undefined(v: T | _NotSetType) -> TypeGuard[_NotSetType]:  # pyright: ignore [reportInvalidTypeVarUse]
    return isinstance(v, _NotSetType)


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
    def committee(
        self,
        id: Opt[int] = NotSet,
        name: Opt[str] = NotSet,
        full_name: Opt[str] = NotSet,
        is_podling: Opt[bool] = NotSet,
        parent_committee_id: Opt[int] = NotSet,
        committee_members: Opt[list[str]] = NotSet,
        committers: Opt[list[str]] = NotSet,
        release_managers: Opt[list[str]] = NotSet,
        vote_policy_id: Opt[int] = NotSet,
        name_in: Opt[list[str]] = NotSet,
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

    def package(
        self,
        artifact_sha3: Opt[str] = NotSet,
        artifact_type: Opt[str] = NotSet,
        filename: Opt[str] = NotSet,
        sha512: Opt[str] = NotSet,
        signature_sha3: Opt[str] = NotSet,
        uploaded: Opt[bool] = NotSet,
        bytes_size: Opt[int] = NotSet,
        release_name: Opt[str] = NotSet,
        _release: bool = False,
        _tasks: bool = False,
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
        if _tasks:
            query = query.options(select_in_load(models.Package.tasks))
        if _release_project:
            query = query.options(select_in_load(models.Package.release, models.Release.project))
        if _release_committee:
            query = query.options(
                select_in_load_nested(models.Package.release, models.Release.project, models.Project.committee)
            )
        return Query(self, query)

    def project(
        self,
        id: Opt[int] = NotSet,
        name: Opt[str] = NotSet,
        full_name: Opt[str] = NotSet,
        is_podling: Opt[bool] = NotSet,
        committee_id: Opt[int] = NotSet,
        vote_policy_id: Opt[int] = NotSet,
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
        fingerprint: Opt[str] = NotSet,
        algorithm: Opt[str] = NotSet,
        length: Opt[int] = NotSet,
        created: Opt[datetime] = NotSet,
        expires: Opt[datetime | None] = NotSet,
        declared_uid: Opt[str | None] = NotSet,
        apache_uid: Opt[str] = NotSet,
        ascii_armored_key: Opt[str] = NotSet,
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
        name: Opt[str] = NotSet,
        stage: Opt[ReleaseStage] = NotSet,
        phase: Opt[ReleasePhase] = NotSet,
        created: Opt[datetime] = NotSet,
        project_id: Opt[int] = NotSet,
        package_managers: Opt[list[str]] = NotSet,
        version: Opt[str] = NotSet,
        sboms: Opt[list[str]] = NotSet,
        vote_policy_id: Opt[int] = NotSet,
        votes: Opt[list[VoteEntry]] = NotSet,
        _project: bool = False,
        _packages: bool = False,
        _vote_policy: bool = False,
        _committee: bool = False,
        _packages_tasks: bool = False,
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
        if _packages_tasks:
            query = query.options(select_in_load_nested(models.Release.packages, models.Package.tasks))

        return Query(self, query)

    def ssh_key(
        self,
        fingerprint: Opt[str] = NotSet,
        key: Opt[str] = NotSet,
        asf_uid: Opt[str] = NotSet,
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
        id: Opt[int] = NotSet,
        status: Opt[TaskStatus] = NotSet,
        task_type: Opt[str] = NotSet,
        task_args: Opt[Any] = NotSet,
        added: Opt[datetime] = NotSet,
        started: Opt[datetime | None] = NotSet,
        pid: Opt[int | None] = NotSet,
        completed: Opt[datetime | None] = NotSet,
        result: Opt[Any | None] = NotSet,
        error: Opt[str | None] = NotSet,
        package_sha3: Opt[str | None] = NotSet,
        _package: bool = False,
        _package_release: bool = False,
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
        if is_defined(package_sha3):
            query = query.where(models.Task.package_sha3 == package_sha3)

        if _package:
            query = query.options(select_in_load(models.Task.package))
        if _package_release:
            query = query.options(select_in_load_nested(models.Task.package, models.Package.release))

        return Query(self, query)

    def vote_policy(
        self,
        id: Opt[int] = NotSet,
        mailto_addresses: Opt[list[str]] = NotSet,
        manual_vote: Opt[bool] = NotSet,
        min_hours: Opt[int] = NotSet,
        release_checklist: Opt[str] = NotSet,
        pause_for_rm: Opt[bool] = NotSet,
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


def init_database(app: base.QuartApp) -> None:
    """
    Creates and initializes the database for a QuartApp.

    The database is created and an AsyncSession is registered as extension for the app.
    Any pending migrations are executed.
    """

    @app.before_serving
    async def create() -> None:
        app_config = config.get()
        engine = create_async_engine(app_config)

        app.extensions["async_session"] = sqlalchemy.ext.asyncio.async_sessionmaker(
            bind=engine, class_=sqlalchemy.ext.asyncio.AsyncSession, expire_on_commit=False
        )
        app.extensions["atr_db_session"] = sqlalchemy.ext.asyncio.async_sessionmaker(
            bind=engine, class_=Session, expire_on_commit=False
        )

        # Set SQLite pragmas for better performance
        # Use 64 MB for the cache_size, and 5000ms for busy_timeout
        async with engine.begin() as conn:
            await conn.execute(sql.text("PRAGMA journal_mode=WAL"))
            await conn.execute(sql.text("PRAGMA synchronous=NORMAL"))
            await conn.execute(sql.text("PRAGMA cache_size=-64000"))
            await conn.execute(sql.text("PRAGMA foreign_keys=ON"))
            await conn.execute(sql.text("PRAGMA busy_timeout=5000"))

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


def init_database_for_worker() -> None:
    global _global_async_sessionmaker

    _LOGGER.info(f"Creating database for worker {os.getpid()}")
    engine = create_async_engine(config.get())
    _global_async_sessionmaker = sqlalchemy.ext.asyncio.async_sessionmaker(
        bind=engine, class_=sqlalchemy.ext.asyncio.AsyncSession, expire_on_commit=False
    )


def create_async_engine(app_config: type[config.AppConfig]) -> sqlalchemy.ext.asyncio.AsyncEngine:
    sqlite_url = f"sqlite+aiosqlite://{app_config.SQLITE_DB_PATH}"
    # Use aiosqlite for async SQLite access
    engine = sqlalchemy.ext.asyncio.create_async_engine(
        sqlite_url,
        connect_args={
            "check_same_thread": False,
            "timeout": 30,
        },
    )

    return engine


def create_async_db_session() -> sqlalchemy.ext.asyncio.AsyncSession:
    """Create a new asynchronous database session."""
    if quart.has_app_context():
        extensions = quart.current_app.extensions
        return util.validate_as_type(extensions["async_session"](), sqlalchemy.ext.asyncio.AsyncSession)
    else:
        if _global_async_sessionmaker is None:
            raise RuntimeError("Global async_sessionmaker not initialized, run init_database() first.")
        return util.validate_as_type(_global_async_sessionmaker(), sqlalchemy.ext.asyncio.AsyncSession)


def session() -> Session:
    """Create a new asynchronous database session."""
    global _global_atr_sessionmaker

    if quart.has_app_context():
        extensions = quart.current_app.extensions
        return util.validate_as_type(extensions["atr_db_session"](), Session)
    else:
        if _global_atr_sessionmaker is None:
            engine = create_async_engine(config.get())
            _global_atr_sessionmaker = sqlalchemy.ext.asyncio.async_sessionmaker(
                bind=engine, class_=Session, expire_on_commit=False
            )
        return util.validate_as_type(_global_atr_sessionmaker(), Session)


# FIXME: this method is deprecated and should be removed
def create_sync_db_engine() -> None:
    """Create a synchronous database engine."""

    global _global_sync_engine

    conf = config.get()
    sqlite_url = f"sqlite://{conf.SQLITE_DB_PATH}"
    _LOGGER.debug(f"Creating sync database engine in process {os.getpid()}")
    _global_sync_engine = sqlalchemy.create_engine(sqlite_url, echo=False)


# FIXME: this method is deprecated and should be removed
def create_sync_db_session() -> sqlalchemy.orm.Session:
    """Create a new synchronous database session."""
    global _global_sync_engine
    if _global_sync_engine is None:
        conf = config.get()
        sqlite_url = f"sqlite://{conf.SQLITE_DB_PATH}"
        _global_sync_engine = sqlalchemy.create_engine(sqlite_url, echo=False)
    return sqlalchemy.orm.Session(_global_sync_engine)


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


def validate_instrumented_attribute(obj: Any) -> orm.InstrumentedAttribute:
    """Check if the given object is an InstrumentedAttribute."""
    if not isinstance(obj, orm.InstrumentedAttribute):
        raise ValueError(f"Object must be an orm.InstrumentedAttribute, got: {type(obj)}")
    return obj
