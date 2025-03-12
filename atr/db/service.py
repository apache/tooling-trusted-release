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

from collections.abc import Sequence
from contextlib import nullcontext

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

import atr.db as db
from atr.db.models import PMC, Release, Task

from . import create_async_db_session


async def get_pmc_by_name(project_name: str, session: AsyncSession | None = None) -> PMC | None:
    """Returns a PMC object by name."""
    async with create_async_db_session() if session is None else nullcontext(session) as db_session:
        statement = select(PMC).where(PMC.project_name == project_name)
        pmc = (await db_session.execute(statement)).scalar_one_or_none()
        return pmc


async def get_pmcs(session: AsyncSession | None = None) -> Sequence[PMC]:
    """Returns a list of PMC objects."""
    async with create_async_db_session() if session is None else nullcontext(session) as db_session:
        # Get all PMCs and their latest releases
        statement = select(PMC).order_by(PMC.project_name)
        pmcs = (await db_session.execute(statement)).scalars().all()
        return pmcs


async def get_release_by_key(storage_key: str) -> Release | None:
    """Get a release by its storage key."""
    async with create_async_db_session() as db_session:
        # Get the release with its PMC and product line
        query = (
            select(Release)
            .where(Release.storage_key == storage_key)
            .options(db.eager_load(Release.pmc))
            .options(db.eager_load(Release.product_line))
        )
        result = await db_session.execute(query)
        return result.scalar_one_or_none()


def get_release_by_key_sync(storage_key: str) -> Release | None:
    """Synchronous version of get_release_by_key for use in background tasks."""
    from atr.db import create_sync_db_session

    with create_sync_db_session() as session:
        # Get the release with its PMC and product line
        query = (
            select(Release)
            .where(Release.storage_key == storage_key)
            .options(db.eager_load(Release.pmc))
            .options(db.eager_load(Release.product_line))
        )
        result = session.execute(query)
        return result.scalar_one_or_none()


async def get_tasks(limit: int, offset: int, session: AsyncSession | None = None) -> tuple[Sequence[Task], int]:
    """Returns a list of Tasks based on limit and offset values together with the total count."""
    async with create_async_db_session() if session is None else nullcontext(session) as db_session:
        statement = select(Task).limit(limit).offset(offset).order_by(Task.id.desc())  # type: ignore
        tasks = (await db_session.execute(statement)).scalars().all()
        count = (await db_session.execute(select(func.count(Task.id)))).scalar_one()  # type: ignore
        return tasks, count
