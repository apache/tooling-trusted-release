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

"""project.py"""

import http.client
from typing import cast

import quart
import sqlalchemy.orm as orm
import sqlmodel

import atr.db as db
import atr.db.models as models
import atr.db.service as service
import atr.routes as routes


@routes.app_route("/projects")
async def root_project_directory() -> str:
    """Main project directory page."""
    async with db.create_async_db_session() as session:
        projects = await service.get_pmcs(session)
        return await quart.render_template("project-directory.html", projects=projects)


@routes.app_route("/projects/<project_name>")
async def root_project_view(project_name: str) -> str:
    async with db.create_async_db_session() as db_session:
        statement = (
            sqlmodel.select(models.PMC)
            .where(models.PMC.project_name == project_name)
            .options(
                orm.selectinload(
                    cast(orm.attributes.InstrumentedAttribute[models.PublicSigningKey], models.PMC.public_signing_keys)
                )
            )
        )

        project = (await db_session.execute(statement)).scalar_one_or_none()

        if not project:
            raise http.client.HTTPException(404)

        return await quart.render_template("project-view.html", project=project, algorithms=routes.algorithms)
