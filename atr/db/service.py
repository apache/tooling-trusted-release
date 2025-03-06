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

from sqlalchemy import func
from sqlmodel import select

from atr.db.models import PMC, Task

from . import create_async_db_session


async def get_pmc_by_name(project_name: str) -> PMC | None:
    async with create_async_db_session() as db_session:
        statement = select(PMC).where(PMC.project_name == project_name)
        pmc = (await db_session.execute(statement)).scalar_one_or_none()
        return pmc


async def get_pmcs() -> Sequence[PMC]:
    async with create_async_db_session() as db_session:
        # Get all PMCs and their latest releases
        statement = select(PMC)
        pmcs = (await db_session.execute(statement)).scalars().all()
        return pmcs


async def get_tasks_paged(limit: int, offset: int) -> tuple[Sequence[Task], int]:
    """Returns a list of Tasks based on limit and offset values together with the total count."""

    async with create_async_db_session() as db_session:
        statement = select(Task).limit(limit).offset(offset).order_by(Task.id.desc())  # type: ignore
        tasks = (await db_session.execute(statement)).scalars().all()
        count = (await db_session.execute(select(func.count(Task.id)))).scalar_one()  # type: ignore
        return tasks, count
