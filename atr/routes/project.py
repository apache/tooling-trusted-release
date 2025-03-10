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

from http.client import HTTPException

from quart import render_template

from atr.db import create_async_db_session
from atr.db.service import get_pmc_by_name, get_pmcs
from atr.routes import algorithms, app_route


@app_route("/projects")
async def root_project_directory() -> str:
    """Main project directory page."""
    async with create_async_db_session() as session:
        projects = await get_pmcs(session)
        return await render_template("project-directory.html", projects=projects)


@app_route("/projects/<project_name>")
async def root_project_view(project_name: str) -> str:
    async with create_async_db_session() as session:
        project = await get_pmc_by_name(project_name, session=session)
        if not project:
            raise HTTPException(404)

        return await render_template("project-view.html", project=project, algorithms=algorithms)
