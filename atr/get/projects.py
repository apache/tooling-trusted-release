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

from typing import TYPE_CHECKING

import atr.blueprints.get as get
import atr.config as config
import atr.db as db
import atr.forms as forms
import atr.models.sql as sql
import atr.shared as shared
import atr.template as template
import atr.web as web

if TYPE_CHECKING:
    import werkzeug.wrappers.response as response


@get.committer("/project/add/<committee_name>")
async def add_project(session: web.Committer, committee_name: str) -> response.Response | str:
    return await shared.projects.add_project(session, committee_name)


@get.public("/projects")
async def projects(session: web.Committer | None) -> str:
    """Main project directory page."""
    async with db.session() as data:
        projects = await data.project(_committee=True).order_by(sql.Project.full_name).all()
        return await template.render("projects.html", projects=projects, empty_form=await forms.Empty.create_form())


@get.committer("/project/select")
async def select(session: web.Committer) -> str:
    """Select a project to work on."""
    user_projects = []
    if session.uid:
        async with db.session() as data:
            # TODO: Move this filtering logic somewhere else
            # The ALLOW_TESTS line allows test projects to be shown
            conf = config.get()
            all_projects = await data.project(status=sql.ProjectStatus.ACTIVE, _committee=True).all()
            user_projects = [
                p
                for p in all_projects
                if p.committee
                and (
                    (conf.ALLOW_TESTS and (p.committee.name == "test"))
                    or (session.uid in p.committee.committee_members)
                    or (session.uid in p.committee.committers)
                    or (session.uid in p.committee.release_managers)
                )
            ]
            user_projects.sort(key=lambda p: p.display_name)

    return await template.render("project-select.html", user_projects=user_projects)


@get.committer("/projects/<name>")
async def view(session: web.Committer, name: str) -> response.Response | str:
    return await shared.projects.view(session, name)
