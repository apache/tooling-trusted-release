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
from collections.abc import Sequence

import sqlalchemy
import sqlalchemy.ext.asyncio
import sqlmodel

import atr.db as db
import atr.db.models as models


async def get_pmc_by_name(name: str, session: sqlalchemy.ext.asyncio.AsyncSession | None = None) -> models.PMC | None:
    """Returns a PMC object by name."""
    async with db.create_async_db_session() if session is None else contextlib.nullcontext(session) as db_session:
        statement = sqlmodel.select(models.PMC).where(models.PMC.name == name)
        pmc = (await db_session.execute(statement)).scalar_one_or_none()
        return pmc


async def get_pmcs(session: sqlalchemy.ext.asyncio.AsyncSession | None = None) -> Sequence[models.PMC]:
    """Returns a list of PMC objects."""
    async with db.create_async_db_session() if session is None else contextlib.nullcontext(session) as db_session:
        # Get all PMCs and their latest releases
        statement = sqlmodel.select(models.PMC).order_by(models.PMC.name)
        pmcs = (await db_session.execute(statement)).scalars().all()
        return pmcs


async def get_release_by_key(storage_key: str) -> models.Release | None:
    """Get a release by its storage key."""
    async with db.create_async_db_session() as db_session:
        # Get the release
        query = (
            sqlmodel.select(models.Release)
            .where(models.Release.storage_key == storage_key)
            .options(db.select_in_load_nested(models.Release.product, models.Product.project, models.Project.pmc))
        )
        result = await db_session.execute(query)
        return result.scalar_one_or_none()


def get_release_by_key_sync(storage_key: str) -> models.Release | None:
    """Synchronous version of get_release_by_key for use in background tasks."""
    with db.create_sync_db_session() as session:
        # Get the release
        query = (
            sqlmodel.select(models.Release)
            .where(models.Release.storage_key == storage_key)
            .options(db.select_in_load_nested(models.Release.product, models.Product.project, models.Project.pmc))
        )
        result = session.execute(query)
        return result.scalar_one_or_none()


async def get_tasks(
    limit: int, offset: int, session: sqlalchemy.ext.asyncio.AsyncSession | None = None
) -> tuple[Sequence[models.Task], int]:
    """Returns a list of Tasks based on limit and offset values together with the total count."""
    async with db.create_async_db_session() if session is None else contextlib.nullcontext(session) as db_session:
        statement = sqlmodel.select(models.Task).limit(limit).offset(offset).order_by(models.Task.id.desc())  # type: ignore
        tasks = (await db_session.execute(statement)).scalars().all()
        count = (await db_session.execute(sqlalchemy.select(sqlalchemy.func.count(models.Task.id)))).scalar_one()  # type: ignore
        return tasks, count
