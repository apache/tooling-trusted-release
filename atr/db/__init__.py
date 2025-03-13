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
_global_sync_engine: sqlalchemy.Engine | None = None


class _DEFAULT: ...


DEFAULT = _DEFAULT()


T = TypeVar("T")


class Query(Generic[T]):
    def __init__(self, session: Session, query: expression.SelectOfScalar[T]):
        self.query = query
        self.session = session

    async def one(self, error: Exception | None = None) -> T | None:
        result = await self.session.execute(self.query)
        item = result.scalar_one_or_none()
        if (item is None) and (error is not None):
            raise error
        return item

    async def all(self) -> Sequence[T]:
        result = await self.session.execute(self.query)
        return result.scalars().all()

    # async def execute(self) -> sqlalchemy.Result[tuple[T]]:
    #     return await self.session.execute(self.query)


class Session(sqlalchemy.ext.asyncio.AsyncSession):
    def committee(
        self,
        id: Any = DEFAULT,
        name: Any = DEFAULT,
        full_name: Any = DEFAULT,
        is_podling: Any = DEFAULT,
        parent_pmc_id: Any = DEFAULT,
        pmc_members: Any = DEFAULT,
        committers: Any = DEFAULT,
        release_managers: Any = DEFAULT,
        vote_policy_id: Any = DEFAULT,
        _public_signing_keys: bool = False,
        _vote_policy: bool = False,
    ) -> Query[models.PMC]:
        query = sqlmodel.select(models.PMC)

        if id is not DEFAULT:
            query = query.where(models.PMC.id == id)
        if name is not DEFAULT:
            query = query.where(models.PMC.name == name)
        if full_name is not DEFAULT:
            query = query.where(models.PMC.full_name == full_name)
        if is_podling is not DEFAULT:
            query = query.where(models.PMC.is_podling == is_podling)
        if parent_pmc_id is not DEFAULT:
            query = query.where(models.PMC.parent_pmc_id == parent_pmc_id)
        if pmc_members is not DEFAULT:
            query = query.where(models.PMC.pmc_members == pmc_members)
        if committers is not DEFAULT:
            query = query.where(models.PMC.committers == committers)
        if release_managers is not DEFAULT:
            query = query.where(models.PMC.release_managers == release_managers)
        if vote_policy_id is not DEFAULT:
            query = query.where(models.PMC.vote_policy_id == vote_policy_id)

        if _public_signing_keys:
            query = query.options(select_in_load(models.PMC.public_signing_keys))
        if _vote_policy:
            query = query.options(select_in_load(models.PMC.vote_policy))

        return Query(self, query)

    def release(
        self,
        storage_key: Any = DEFAULT,
        stage: Any = DEFAULT,
        phase: Any = DEFAULT,
        created: Any = DEFAULT,
        product_id: Any = DEFAULT,
        package_managers: Any = DEFAULT,
        version: Any = DEFAULT,
        sboms: Any = DEFAULT,
        vote_policy_id: Any = DEFAULT,
        votes: Any = DEFAULT,
        _product: bool = False,
        _packages: bool = False,
        _vote_policy: bool = False,
        _product_project_pmc: bool = False,
        _packages_tasks: bool = False,
    ) -> Query[models.Release]:
        query = sqlmodel.select(models.Release)

        if storage_key is not DEFAULT:
            query = query.where(models.Release.storage_key == storage_key)
        if stage is not DEFAULT:
            query = query.where(models.Release.stage == stage)
        if phase is not DEFAULT:
            query = query.where(models.Release.phase == phase)
        if created is not DEFAULT:
            query = query.where(models.Release.created == created)
        if product_id is not DEFAULT:
            query = query.where(models.Release.product_id == product_id)
        if package_managers is not DEFAULT:
            query = query.where(models.Release.package_managers == package_managers)
        if version is not DEFAULT:
            query = query.where(models.Release.version == version)
        if sboms is not DEFAULT:
            query = query.where(models.Release.sboms == sboms)
        if vote_policy_id is not DEFAULT:
            query = query.where(models.Release.vote_policy_id == vote_policy_id)
        if votes is not DEFAULT:
            query = query.where(models.Release.votes == votes)

        if _product:
            query = query.options(select_in_load(models.Release.product))
        if _packages:
            query = query.options(select_in_load(models.Release.packages))
        if _vote_policy:
            query = query.options(select_in_load(models.Release.vote_policy))
        if _product_project_pmc:
            query = query.options(
                select_in_load_nested(models.Release.product, models.Product.project, models.Project.pmc)
            )
        if _packages_tasks:
            query = query.options(select_in_load_nested(models.Release.packages, models.Package.tasks))

        return Query(self, query)

    def package(
        self,
        artifact_sha3: Any = DEFAULT,
        artifact_type: Any = DEFAULT,
        filename: Any = DEFAULT,
        sha512: Any = DEFAULT,
        signature_sha3: Any = DEFAULT,
        uploaded: Any = DEFAULT,
        bytes_size: Any = DEFAULT,
        release_key: Any = DEFAULT,
        _release: bool = False,
        _tasks: bool = False,
        _release_product: bool = False,
        _release_pmc: bool = False,
    ) -> Query[models.Package]:
        query = sqlmodel.select(models.Package)

        if artifact_sha3 is not DEFAULT:
            query = query.where(models.Package.artifact_sha3 == artifact_sha3)
        if artifact_type is not DEFAULT:
            query = query.where(models.Package.artifact_type == artifact_type)
        if filename is not DEFAULT:
            query = query.where(models.Package.filename == filename)
        if sha512 is not DEFAULT:
            query = query.where(models.Package.sha512 == sha512)
        if signature_sha3 is not DEFAULT:
            query = query.where(models.Package.signature_sha3 == signature_sha3)
        if uploaded is not DEFAULT:
            query = query.where(models.Package.uploaded == uploaded)
        if bytes_size is not DEFAULT:
            query = query.where(models.Package.bytes_size == bytes_size)
        if release_key is not DEFAULT:
            query = query.where(models.Package.release_key == release_key)
        if _release:
            query = query.options(select_in_load(models.Package.release))
        if _tasks:
            query = query.options(select_in_load(models.Package.tasks))
        if _release_product:
            query = query.options(select_in_load(models.Package.release, models.Release.product))
        if _release_pmc:
            query = query.options(
                select_in_load_nested(
                    models.Package.release, models.Release.product, models.Product.project, models.Project.pmc
                )
            )
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
    extensions = quart.current_app.extensions
    return util.validate_as_type(extensions["atr_db_session"](), Session)


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
    assert _global_sync_engine is not None
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
