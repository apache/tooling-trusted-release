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


def is_project_lead(project: models.Project, user_id: str) -> bool:
    if project.committee is None:
        raise RuntimeError(f"Committee for project {project.name} not set")
    return user_id in project.committee.committee_members


async def get_committee_by_name(
    name: str, session: sqlalchemy.ext.asyncio.AsyncSession | None = None
) -> models.Committee | None:
    """Returns a Committee object by name."""
    async with db.create_async_db_session() if session is None else contextlib.nullcontext(session) as db_session:
        statement = sqlmodel.select(models.Committee).where(models.Committee.name == name)
        committee = (await db_session.execute(statement)).scalar_one_or_none()
        return committee


async def get_committees(session: sqlalchemy.ext.asyncio.AsyncSession | None = None) -> Sequence[models.Committee]:
    """Returns a list of Committee objects."""
    async with db.create_async_db_session() if session is None else contextlib.nullcontext(session) as db_session:
        # Get all Committees
        statement = sqlmodel.select(models.Committee).order_by(models.Committee.name)
        committees = (await db_session.execute(statement)).scalars().all()
        return committees


async def get_release_by_name(name: str) -> models.Release | None:
    """Get a release by its name."""
    async with db.create_async_db_session() as db_session:
        # Get the release
        query = (
            sqlmodel.select(models.Release)
            .where(models.Release.name == name)
            .options(db.select_in_load_nested(models.Release.project, models.Project.committee))
        )
        result = await db_session.execute(query)
        return result.scalar_one_or_none()


def get_release_by_name_sync(name: str) -> models.Release | None:
    """Synchronous version of get_release_by_name for use in background tasks."""
    with db.create_sync_db_session() as session:
        # Get the release
        query = (
            sqlmodel.select(models.Release)
            .where(models.Release.name == name)
            .options(db.select_in_load_nested(models.Release.project, models.Project.committee))
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
