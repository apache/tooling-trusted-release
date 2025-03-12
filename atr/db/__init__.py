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

import logging
import os
from typing import Any, Final

import alembic.config as config
import quart
import sqlalchemy
import sqlalchemy.ext.asyncio
import sqlalchemy.orm as orm
import sqlalchemy.sql as sql
import sqlmodel

import atr.util as util
from asfquart.base import QuartApp

_LOGGER: Final = logging.getLogger(__name__)

_global_sync_engine: sqlalchemy.Engine | None = None


def create_database(app: QuartApp) -> None:
    @app.before_serving
    async def create() -> None:
        project_root = app.config["PROJECT_ROOT"]
        sqlite_db_path = app.config["SQLITE_DB_PATH"]
        sqlite_url = f"sqlite+aiosqlite://{sqlite_db_path}"
        # Use aiosqlite for async SQLite access
        engine = sqlalchemy.ext.asyncio.create_async_engine(
            sqlite_url,
            connect_args={
                "check_same_thread": False,
                "timeout": 30,
            },
        )

        # Create async session factory
        app.extensions["async_session"] = sqlalchemy.ext.asyncio.async_sessionmaker(
            bind=engine, class_=sqlalchemy.ext.asyncio.AsyncSession, expire_on_commit=False
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
        alembic_ini_path = os.path.join(project_root, "alembic.ini")
        alembic_cfg = config.Config(alembic_ini_path)
        # Override the migrations directory location to use project root
        # TODO: Is it possible to set this in alembic.ini?
        alembic_cfg.set_main_option("script_location", os.path.join(project_root, "migrations"))
        # Set the database URL in the config
        alembic_cfg.set_main_option("sqlalchemy.url", sqlite_url)
        # command.upgrade(alembic_cfg, "head")

        # Create any tables that might be missing
        async with engine.begin() as conn:
            await conn.run_sync(sqlmodel.SQLModel.metadata.create_all)


def create_async_db_session() -> sqlalchemy.ext.asyncio.AsyncSession:
    """Create a new asynchronous database session."""
    if quart.has_app_context():
        extensions = quart.current_app.extensions
        return util.validate_as_type(extensions["async_session"](), sqlalchemy.ext.asyncio.AsyncSession)

    import atr.config as config

    conf = config.get()
    sqlite_url = f"sqlite+aiosqlite://{conf.SQLITE_DB_PATH}"
    engine = sqlalchemy.ext.asyncio.create_async_engine(
        sqlite_url,
        connect_args={
            "check_same_thread": False,
            "timeout": 30,
        },
    )
    return sqlalchemy.ext.asyncio.async_sessionmaker(
        bind=engine, class_=sqlalchemy.ext.asyncio.AsyncSession, expire_on_commit=False
    )()


def create_sync_db_engine() -> None:
    """Create a synchronous database engine."""
    import atr.config as config

    global _global_sync_engine

    conf = config.get()
    sqlite_url = f"sqlite://{conf.SQLITE_DB_PATH}"
    _LOGGER.debug(f"Creating sync database engine in process {os.getpid()}")
    _global_sync_engine = sqlalchemy.create_engine(sqlite_url, echo=False)


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


def select_in_load_nested(parent: Any, child: Any) -> orm.strategy_options._AbstractLoad:
    """Eagerly load the given nested entities from the query."""
    if not isinstance(parent, orm.InstrumentedAttribute):
        raise ValueError(f"Parent must be an orm.InstrumentedAttribute, got: {type(parent)}")
    if not isinstance(child, orm.InstrumentedAttribute):
        raise ValueError(f"Child must be an orm.InstrumentedAttribute, got: {type(child)}")
    return orm.selectinload(parent).selectinload(child)


def validate_instrumented_attribute(obj: Any) -> orm.InstrumentedAttribute:
    """Check if the given object is an InstrumentedAttribute."""
    if not isinstance(obj, orm.InstrumentedAttribute):
        raise ValueError(f"Object must be an orm.InstrumentedAttribute, got: {type(obj)}")
    return obj
