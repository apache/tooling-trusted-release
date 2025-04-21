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
import quart
import sqlmodel
import werkzeug.wrappers.response as response
from sqlalchemy.orm import selectinload

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.user as user


@routes.public("/")
async def index() -> response.Response | str:
    """Show public info or an entry portal for participants."""
    session_data = await asfquart.session.read()
    if session_data:
        uid = session_data.get("uid")
        if not uid:
            return await quart.render_template("index-public.html")

        phase_sequence = ["Compose", "Vote", "Announce"]
        phase_index_map = {
            models.ReleasePhase.RELEASE_CANDIDATE_DRAFT: 0,
            models.ReleasePhase.RELEASE_CANDIDATE: 1,
            models.ReleasePhase.RELEASE_PREVIEW: 2,
        }

        async with db.session() as data:
            user_projects = await user.projects(uid)
            user_projects.sort(key=lambda p: p.display_name)

            projects_with_releases = []
            projects_without_releases = []

            active_phases = list(phase_index_map.keys())
            for project in user_projects:
                stmt = (
                    sqlmodel.select(models.Release)
                    .where(
                        models.Release.project_id == project.id,
                        db.validate_instrumented_attribute(models.Release.phase).in_(active_phases),
                    )
                    .options(selectinload(db.validate_instrumented_attribute(models.Release.project)))
                    .order_by(db.validate_instrumented_attribute(models.Release.created).desc())
                )
                result = await data.execute(stmt)
                active_releases = result.scalars().all()
                completed_releases = (
                    len(await data.release(phase=models.ReleasePhase.RELEASE, project_id=project.id).all()) > 0
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
            if not isinstance(project, models.Project):
                return ""
            return project.display_name

        all_projects.sort(key=sort_key)

        return await quart.render_template(
            "index-committer.html",
            all_projects=all_projects,
            phase_sequence=phase_sequence,
            phase_index_map=phase_index_map,
            format_datetime=routes.format_datetime,
        )

    # Public view
    return await quart.render_template("index-public.html")


@routes.public("/tutorial")
async def tutorial() -> str:
    """Tutorial page."""
    return await quart.render_template("tutorial.html")
