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

from quart import render_template

from asfquart.base import ASFQuartException
from atr.db.service import get_pmc_by_name, get_pmcs
from atr.routes import app_route


@app_route("/project/directory")
async def root_project_directory() -> str:
    """Main project directory page."""
    projects = await get_pmcs()
    return await render_template("project-directory.html", projects=projects)


@app_route("/project/list")
async def root_project_list() -> list[dict]:
    """List all projects in the database."""
    pmcs = await get_pmcs()

    return [
        {
            "id": pmc.id,
            "project_name": pmc.project_name,
            "pmc_members": pmc.pmc_members,
            "committers": pmc.committers,
            "release_managers": pmc.release_managers,
        }
        for pmc in pmcs
    ]


@app_route("/project/<project_name>")
async def root_project_project_name(project_name: str) -> dict:
    """Get a specific project by project name."""
    pmc = await get_pmc_by_name(project_name)
    if not pmc:
        raise ASFQuartException("PMC not found", errorcode=404)

    return {
        "id": pmc.id,
        "project_name": pmc.project_name,
        "pmc_members": pmc.pmc_members,
        "committers": pmc.committers,
        "release_managers": pmc.release_managers,
    }
