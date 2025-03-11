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
import werkzeug.wrappers.response as response

import asfquart.session as session
import atr.db as db
import atr.db.models as models
import atr.db.service as service
import atr.routes as routes
from asfquart import base


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
                ),
                orm.selectinload(cast(orm.attributes.InstrumentedAttribute[models.VotePolicy], models.PMC.vote_policy)),
            )
        )

        project = (await db_session.execute(statement)).scalar_one_or_none()

        if not project:
            raise http.client.HTTPException(404)

        return await quart.render_template("project-view.html", project=project, algorithms=routes.algorithms)


@routes.app_route("/projects/<project_name>/voting/create", methods=["GET", "POST"])
async def root_project_voting_policy_add(project_name: str) -> response.Response | str:
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    async with db.create_async_db_session() as db_session:
        statement = sqlmodel.select(models.PMC).where(models.PMC.project_name == project_name)
        pmc = (await db_session.execute(statement)).scalar_one_or_none()

        if not pmc:
            raise base.ASFQuartException("PMC not found", errorcode=404)
        elif pmc.project_name not in web_session.committees:
            raise base.ASFQuartException(
                f"You must be a PMC member of {pmc.display_name} to submit a voting policy", errorcode=403
            )

    # For POST requests, handle the release creation
    if quart.request.method == "POST":
        return await voting_policy_add_post(web_session, quart.request)

    # For GET requests, show the form
    return await quart.render_template(
        "voting-policy-add.html",
        asf_id=web_session.uid,
        project=pmc,
    )


async def voting_policy_add_post(session: session.ClientSession, request: quart.Request) -> response.Response:
    form = await routes.get_form(request)

    project_name = form.get("project_name")
    if not project_name:
        raise base.ASFQuartException("Project name is required", errorcode=400)

    mailto_addresses = form.get("mailto_addresses")
    if not mailto_addresses:
        raise base.ASFQuartException("Mailto addresses are required", errorcode=400)

    manual_vote = bool(form.get("manual_vote"))
    if not manual_vote:
        raise base.ASFQuartException("Manual vote is required", errorcode=400)

    min_hours = form.get("min_hours")
    if not min_hours:
        raise base.ASFQuartException("Min hours is required", errorcode=400)

    release_checklist = form.get("release_checklist")
    if not release_checklist:
        release_checklist = ""

    pause_for_rm = bool(form.get("pause_for_rm"))
    if not pause_for_rm:
        raise base.ASFQuartException("Pause for RM is required", errorcode=400)

    async with db.create_async_db_session() as db_session:
        async with db_session.begin():
            statement = sqlmodel.select(models.PMC).where(models.PMC.project_name == project_name)
            pmc = (await db_session.execute(statement)).scalar_one_or_none()
            if not pmc:
                raise base.ASFQuartException("PMC not found", errorcode=404)
            elif pmc.project_name not in session.committees:
                raise base.ASFQuartException(
                    f"You must be a PMC member of {pmc.display_name} to submit a voting policy", errorcode=403
                )

            vote_policy = models.VotePolicy(
                mailto_addresses=mailto_addresses,
                manual_vote=manual_vote,
                min_hours=min_hours,
                release_checklist=release_checklist,
                pause_for_rm=pause_for_rm,
            )
            db_session.add(vote_policy)

    # Redirect to the add package page with the storage token
    return quart.redirect(quart.url_for("root_project_view", project_name=project_name))
