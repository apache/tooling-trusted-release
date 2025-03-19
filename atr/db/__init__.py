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
from typing import TYPE_CHECKING, Any, Final, Generic, TypeVar

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

    import asfquart.base as base

_LOGGER: Final = logging.getLogger(__name__)

_global_async_sessionmaker: sqlalchemy.ext.asyncio.async_sessionmaker | None = None
_global_atr_sessionmaker: sqlalchemy.ext.asyncio.async_sessionmaker | None = None
_global_sync_engine: sqlalchemy.Engine | None = None


class _DefaultArgument: ...


_DEFAULT: Final = _DefaultArgument()


T = TypeVar("T")


class Query(Generic[T]):
    def __init__(self, session: Session, query: expression.SelectOfScalar[T]):
        self.query = query
        self.session = session

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
        id: Any = _DEFAULT,
        name: Any = _DEFAULT,
        full_name: Any = _DEFAULT,
        is_podling: Any = _DEFAULT,
        parent_committee_id: Any = _DEFAULT,
        committee_members: Any = _DEFAULT,
        committers: Any = _DEFAULT,
        release_managers: Any = _DEFAULT,
        vote_policy_id: Any = _DEFAULT,
        name_in: list[str] | _DefaultArgument = _DEFAULT,
        _public_signing_keys: bool = False,
        _vote_policy: bool = False,
    ) -> Query[models.Committee]:
        query = sqlmodel.select(models.Committee)

        if id is not _DEFAULT:
            query = query.where(models.Committee.id == id)
        if name is not _DEFAULT:
            query = query.where(models.Committee.name == name)
        if full_name is not _DEFAULT:
            query = query.where(models.Committee.full_name == full_name)
        if is_podling is not _DEFAULT:
            query = query.where(models.Committee.is_podling == is_podling)
        if parent_committee_id is not _DEFAULT:
            query = query.where(models.Committee.parent_committee_id == parent_committee_id)
        if committee_members is not _DEFAULT:
            query = query.where(models.Committee.committee_members == committee_members)
        if committers is not _DEFAULT:
            query = query.where(models.Committee.committers == committers)
        if release_managers is not _DEFAULT:
            query = query.where(models.Committee.release_managers == release_managers)
        if vote_policy_id is not _DEFAULT:
            query = query.where(models.Committee.vote_policy_id == vote_policy_id)

        if not isinstance(name_in, _DefaultArgument):
            models_committee_name = validate_instrumented_attribute(models.Committee.name)
            query = query.where(models_committee_name.in_(name_in))

        if _public_signing_keys:
            query = query.options(select_in_load(models.Committee.public_signing_keys))
        if _vote_policy:
            query = query.options(select_in_load(models.Committee.vote_policy))

        return Query(self, query)

    def package(
        self,
        artifact_sha3: Any = _DEFAULT,
        artifact_type: Any = _DEFAULT,
        filename: Any = _DEFAULT,
        sha512: Any = _DEFAULT,
        signature_sha3: Any = _DEFAULT,
        uploaded: Any = _DEFAULT,
        bytes_size: Any = _DEFAULT,
        release_key: Any = _DEFAULT,
        _release: bool = False,
        _tasks: bool = False,
        _release_project: bool = False,
        _release_committee: bool = False,
    ) -> Query[models.Package]:
        query = sqlmodel.select(models.Package)

        if artifact_sha3 is not _DEFAULT:
            query = query.where(models.Package.artifact_sha3 == artifact_sha3)
        if artifact_type is not _DEFAULT:
            query = query.where(models.Package.artifact_type == artifact_type)
        if filename is not _DEFAULT:
            query = query.where(models.Package.filename == filename)
        if sha512 is not _DEFAULT:
            query = query.where(models.Package.sha512 == sha512)
        if signature_sha3 is not _DEFAULT:
            query = query.where(models.Package.signature_sha3 == signature_sha3)
        if uploaded is not _DEFAULT:
            query = query.where(models.Package.uploaded == uploaded)
        if bytes_size is not _DEFAULT:
            query = query.where(models.Package.bytes_size == bytes_size)
        if release_key is not _DEFAULT:
            query = query.where(models.Package.release_key == release_key)
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
        id: Any = _DEFAULT,
        name: Any = _DEFAULT,
        full_name: Any = _DEFAULT,
        is_podling: Any = _DEFAULT,
        committee_id: Any = _DEFAULT,
        vote_policy_id: Any = _DEFAULT,
        _committee: bool = False,
        _releases: bool = False,
        _distribution_channels: bool = False,
        _vote_policy: bool = False,
        _committee_public_signing_keys: bool = False,
    ) -> Query[models.Project]:
        query = sqlmodel.select(models.Project)

        if id is not _DEFAULT:
            query = query.where(models.Project.id == id)
        if name is not _DEFAULT:
            query = query.where(models.Project.name == name)
        if full_name is not _DEFAULT:
            query = query.where(models.Project.full_name == full_name)
        if is_podling is not _DEFAULT:
            query = query.where(models.Project.is_podling == is_podling)
        if committee_id is not _DEFAULT:
            query = query.where(models.Project.committee_id == committee_id)
        if vote_policy_id is not _DEFAULT:
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
        fingerprint: Any = _DEFAULT,
        algorithm: Any = _DEFAULT,
        length: Any = _DEFAULT,
        created: Any = _DEFAULT,
        expires: Any = _DEFAULT,
        declared_uid: Any = _DEFAULT,
        apache_uid: Any = _DEFAULT,
        ascii_armored_key: Any = _DEFAULT,
        _committees: bool = False,
    ) -> Query[models.PublicSigningKey]:
        query = sqlmodel.select(models.PublicSigningKey)

        if fingerprint is not _DEFAULT:
            query = query.where(models.PublicSigningKey.fingerprint == fingerprint)
        if algorithm is not _DEFAULT:
            query = query.where(models.PublicSigningKey.algorithm == algorithm)
        if length is not _DEFAULT:
            query = query.where(models.PublicSigningKey.length == length)
        if created is not _DEFAULT:
            query = query.where(models.PublicSigningKey.created == created)
        if expires is not _DEFAULT:
            query = query.where(models.PublicSigningKey.expires == expires)
        if declared_uid is not _DEFAULT:
            query = query.where(models.PublicSigningKey.declared_uid == declared_uid)
        if apache_uid is not _DEFAULT:
            query = query.where(models.PublicSigningKey.apache_uid == apache_uid)
        if ascii_armored_key is not _DEFAULT:
            query = query.where(models.PublicSigningKey.ascii_armored_key == ascii_armored_key)

        if _committees:
            query = query.options(select_in_load(models.PublicSigningKey.committees))

        return Query(self, query)

    def release(
        self,
        storage_key: Any = _DEFAULT,
        stage: Any = _DEFAULT,
        phase: Any = _DEFAULT,
        created: Any = _DEFAULT,
        project_id: Any = _DEFAULT,
        package_managers: Any = _DEFAULT,
        version: Any = _DEFAULT,
        sboms: Any = _DEFAULT,
        vote_policy_id: Any = _DEFAULT,
        votes: Any = _DEFAULT,
        _project: bool = False,
        _packages: bool = False,
        _vote_policy: bool = False,
        _committee: bool = False,
        _packages_tasks: bool = False,
    ) -> Query[models.Release]:
        query = sqlmodel.select(models.Release)

        if storage_key is not _DEFAULT:
            query = query.where(models.Release.storage_key == storage_key)
        if stage is not _DEFAULT:
            query = query.where(models.Release.stage == stage)
        if phase is not _DEFAULT:
            query = query.where(models.Release.phase == phase)
        if created is not _DEFAULT:
            query = query.where(models.Release.created == created)
        if project_id is not _DEFAULT:
            query = query.where(models.Release.project_id == project_id)
        if package_managers is not _DEFAULT:
            query = query.where(models.Release.package_managers == package_managers)
        if version is not _DEFAULT:
            query = query.where(models.Release.version == version)
        if sboms is not _DEFAULT:
            query = query.where(models.Release.sboms == sboms)
        if vote_policy_id is not _DEFAULT:
            query = query.where(models.Release.vote_policy_id == vote_policy_id)
        if votes is not _DEFAULT:
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
        fingerprint: Any = _DEFAULT,
        key: Any = _DEFAULT,
        asf_uid: Any = _DEFAULT,
    ) -> Query[models.SSHKey]:
        query = sqlmodel.select(models.SSHKey)

        if fingerprint is not _DEFAULT:
            query = query.where(models.SSHKey.fingerprint == fingerprint)
        if key is not _DEFAULT:
            query = query.where(models.SSHKey.key == key)
        if asf_uid is not _DEFAULT:
            query = query.where(models.SSHKey.asf_uid == asf_uid)

        return Query(self, query)

    def task(
        self,
        id: Any = _DEFAULT,
        status: Any = _DEFAULT,
        task_type: Any = _DEFAULT,
        task_args: Any = _DEFAULT,
        added: Any = _DEFAULT,
        started: Any = _DEFAULT,
        pid: Any = _DEFAULT,
        completed: Any = _DEFAULT,
        result: Any = _DEFAULT,
        error: Any = _DEFAULT,
        package_sha3: Any = _DEFAULT,
        _package: bool = False,
        _package_release: bool = False,
    ) -> Query[models.Task]:
        query = sqlmodel.select(models.Task)

        if id is not _DEFAULT:
            query = query.where(models.Task.id == id)
        if status is not _DEFAULT:
            query = query.where(models.Task.status == status)
        if task_type is not _DEFAULT:
            query = query.where(models.Task.task_type == task_type)
        if task_args is not _DEFAULT:
            query = query.where(models.Task.task_args == task_args)
        if added is not _DEFAULT:
            query = query.where(models.Task.added == added)
        if started is not _DEFAULT:
            query = query.where(models.Task.started == started)
        if pid is not _DEFAULT:
            query = query.where(models.Task.pid == pid)
        if completed is not _DEFAULT:
            query = query.where(models.Task.completed == completed)
        if result is not _DEFAULT:
            query = query.where(models.Task.result == result)
        if error is not _DEFAULT:
            query = query.where(models.Task.error == error)
        if package_sha3 is not _DEFAULT:
            query = query.where(models.Task.package_sha3 == package_sha3)

        if _package:
            query = query.options(select_in_load(models.Task.package))
        if _package_release:
            query = query.options(select_in_load_nested(models.Task.package, models.Package.release))

        return Query(self, query)

    def vote_policy(
        self,
        id: Any = _DEFAULT,
        mailto_addresses: Any = _DEFAULT,
        manual_vote: Any = _DEFAULT,
        min_hours: Any = _DEFAULT,
        release_checklist: Any = _DEFAULT,
        pause_for_rm: Any = _DEFAULT,
        _committees: bool = False,
        _projects: bool = False,
        _releases: bool = False,
    ) -> Query[models.VotePolicy]:
        query = sqlmodel.select(models.VotePolicy)

        if id is not _DEFAULT:
            query = query.where(models.VotePolicy.id == id)
        if mailto_addresses is not _DEFAULT:
            query = query.where(models.VotePolicy.mailto_addresses == mailto_addresses)
        if manual_vote is not _DEFAULT:
            query = query.where(models.VotePolicy.manual_vote == manual_vote)
        if min_hours is not _DEFAULT:
            query = query.where(models.VotePolicy.min_hours == min_hours)
        if release_checklist is not _DEFAULT:
            query = query.where(models.VotePolicy.release_checklist == release_checklist)
        if pause_for_rm is not _DEFAULT:
            query = query.where(models.VotePolicy.pause_for_rm == pause_for_rm)

        if _committees:
            query = query.options(select_in_load(models.VotePolicy.committees))
        if _projects:
            query = query.options(select_in_load(models.VotePolicy.projects))
        if _releases:
            query = query.options(select_in_load(models.VotePolicy.releases))

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
