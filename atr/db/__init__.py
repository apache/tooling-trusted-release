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

# from alembic import command
from alembic.config import Config
from quart import current_app
from sqlalchemy import Engine, create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.sql import text
from sqlmodel import SQLModel

from asfquart.base import QuartApp

_LOGGER = logging.getLogger(__name__)


def create_database(app: QuartApp) -> None:
    @app.before_serving
    async def create() -> None:
        project_root = app.config["PROJECT_ROOT"]
        sqlite_db_path = app.config["SQLITE_DB_PATH"]
        sqlite_url = f"sqlite+aiosqlite://{sqlite_db_path}"
        # Use aiosqlite for async SQLite access
        engine = create_async_engine(
            sqlite_url,
            connect_args={
                "check_same_thread": False,
                "timeout": 30,
            },
        )

        # Create async session factory
        async_session = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
        app.async_session = async_session  # type: ignore

        # Set SQLite pragmas for better performance
        # Use 64 MB for the cache_size, and 5000ms for busy_timeout
        async with engine.begin() as conn:
            await conn.execute(text("PRAGMA journal_mode=WAL"))
            await conn.execute(text("PRAGMA synchronous=NORMAL"))
            await conn.execute(text("PRAGMA cache_size=-64000"))
            await conn.execute(text("PRAGMA foreign_keys=ON"))
            await conn.execute(text("PRAGMA busy_timeout=5000"))

        # Run any pending migrations
        # In dev we'd do this first:
        # poetry run alembic revision --autogenerate -m "description"
        # Then review the generated migration in migrations/versions/ and commit it
        alembic_ini_path = os.path.join(project_root, "alembic.ini")
        alembic_cfg = Config(alembic_ini_path)
        # Override the migrations directory location to use project root
        # TODO: Is it possible to set this in alembic.ini?
        alembic_cfg.set_main_option("script_location", os.path.join(project_root, "migrations"))
        # Set the database URL in the config
        alembic_cfg.set_main_option("sqlalchemy.url", sqlite_url)
        # command.upgrade(alembic_cfg, "head")

        # Create any tables that might be missing
        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)


def create_async_db_session() -> AsyncSession:
    """Create a new asynchronous database session."""
    return current_app.async_session()  # type: ignore


_SYNC_ENGINE: Engine | None = None


def create_sync_db_engine() -> None:
    """Create a synchronous database engine."""
    from atr.config import get_config

    global _SYNC_ENGINE

    config = get_config()
    sqlite_url = f"sqlite://{config.SQLITE_DB_PATH}"
    _LOGGER.debug(f"Creating sync database engine in process {os.getpid()}")
    _SYNC_ENGINE = create_engine(sqlite_url, echo=False)


def create_sync_db_session() -> Session:
    """Create a new synchronous database session."""
    global _SYNC_ENGINE
    assert _SYNC_ENGINE is not None
    return Session(_SYNC_ENGINE)
