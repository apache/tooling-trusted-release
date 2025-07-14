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

"""root.py"""

import asfquart.session
import sqlalchemy.orm as orm
import sqlmodel
import werkzeug.wrappers.response as response

import atr.db as db
import atr.models.sql as sql
import atr.routes as routes
import atr.template as template
import atr.user as user
import atr.util as util


@routes.public("/")
async def index() -> response.Response | str:
    """Show public info or an entry portal for participants."""
    session_data = await asfquart.session.read()
    if session_data:
        uid = session_data.get("uid")
        if not uid:
            return await template.render("index-public.html")

        phase_sequence = ["Compose", "Vote", "Finish"]
        phase_index_map = {
            sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT: 0,
            sql.ReleasePhase.RELEASE_CANDIDATE: 1,
            sql.ReleasePhase.RELEASE_PREVIEW: 2,
        }

        async with db.session() as data:
            user_projects = await user.projects(uid)
            user_projects.sort(key=lambda p: p.display_name.lower())

            projects_with_releases = []
            projects_without_releases = []

            active_phases = list(phase_index_map.keys())
            for project in user_projects:
                stmt = (
                    sqlmodel.select(sql.Release)
                    .where(
                        sql.Release.project_name == project.name,
                        sql.validate_instrumented_attribute(sql.Release.phase).in_(active_phases),
                    )
                    .options(orm.selectinload(sql.validate_instrumented_attribute(sql.Release.project)))
                    .order_by(sql.validate_instrumented_attribute(sql.Release.created).desc())
                )
                result = await data.execute(stmt)
                active_releases = result.scalars().all()
                completed_releases = (
                    len(await data.release(phase=sql.ReleasePhase.RELEASE, project_name=project.name).all()) > 0
                )

                if active_releases:
                    projects_with_releases.append(
                        {
                            "project": project,
                            "active_releases": active_releases,
                            "completed_releases": completed_releases,
                        }
                    )
                else:
                    projects_without_releases.append(
                        {"project": project, "active_releases": [], "completed_releases": completed_releases}
                    )

        all_projects = projects_with_releases + projects_without_releases

        def sort_key(item: dict) -> str:
            project = item["project"]
            if not isinstance(project, sql.Project):
                return ""
            return project.display_name.lower()

        all_projects.sort(key=sort_key)

        return await template.render(
            "index-committer.html",
            all_projects=all_projects,
            phase_sequence=phase_sequence,
            phase_index_map=phase_index_map,
            format_datetime=util.format_datetime,
        )

    # Public view
    return await template.render("index-public.html")


@routes.committer("/todo", methods=["POST"])
async def todo(session: routes.CommitterSession) -> str:
    """POST target for development."""
    return await template.render("todo.html")


@routes.committer("/tutorial")
async def tutorial(session: routes.CommitterSession) -> str:
    """Tutorial page."""
    return await template.render("tutorial.html")
