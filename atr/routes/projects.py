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

import asfquart.base as base
import asfquart.session as session
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.util as util


class CreateVotePolicyForm(util.QuartFormTyped):
    project_name = wtforms.HiddenField("project_name")
    mailto_addresses = wtforms.StringField(
        "Email",
        validators=[
            wtforms.validators.InputRequired("Please provide a valid email address"),
            wtforms.validators.Email(),
        ],
    )
    min_hours = wtforms.IntegerField(
        "Minimum Voting Period:", widget=wtforms.widgets.NumberInput(min=0, max=144), default=72
    )
    manual_vote = wtforms.BooleanField("Voting Process:")
    release_checklist = wtforms.StringField("Release Checklist:", widget=wtforms.widgets.TextArea())
    pause_for_rm = wtforms.BooleanField("Pause for RM:")

    submit = wtforms.SubmitField("Add")


async def add_voting_policy(session: session.ClientSession, form: CreateVotePolicyForm) -> response.Response:
    name = str(form.project_name.data)

    async with db.session() as data:
        async with data.begin():
            committee = await data.committee(name=name).demand(
                base.ASFQuartException("Committee not found", errorcode=404)
            )
            if committee.name not in session.committees:
                raise base.ASFQuartException(
                    f"You must be a committee member of {committee.display_name} to submit a voting policy",
                    errorcode=403,
                )

            vote_policy = models.VotePolicy(
                mailto_addresses=[util.unwrap(form.mailto_addresses.data)],
                manual_vote=form.manual_vote.data,
                min_hours=util.unwrap(form.min_hours.data),
                release_checklist=util.unwrap(form.release_checklist.data),
                pause_for_rm=form.pause_for_rm.data,
            )
            data.add(vote_policy)

    # Redirect to the add package page with the storage token
    return quart.redirect(quart.url_for("root_project_view", name=name))


@routes.app_route("/projects")
async def root_project_directory() -> str:
    """Main project directory page."""
    async with db.session() as data:
        projects = await data.project(_committee=True).order_by(models.Project.name).all()
        return await quart.render_template("project-directory.html", projects=projects)


@routes.app_route("/projects/<name>")
async def root_project_view(name: str) -> str:
    async with db.session() as data:
        project = await data.project(name=name, _committee_public_signing_keys=True, _vote_policy=True).demand(
            http.client.HTTPException(404)
        )
        return await quart.render_template("project-view.html", project=project, algorithms=routes.algorithms)


@routes.app_route("/projects/<name>/voting/create", methods=["GET", "POST"])
async def root_project_voting_policy_add(name: str) -> response.Response | str:
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    async with db.session() as data:
        project = await data.project(name=name, _committee=True).demand(
            base.ASFQuartException("Project not found", errorcode=404)
        )
        if project.committee is None:
            raise base.ASFQuartException("Project is not associated with a committee", errorcode=404)
        if project.committee.name not in web_session.committees:
            raise base.ASFQuartException(
                f"You must be a committee member of {project.display_name} to submit a voting policy", errorcode=403
            )

    form = await CreateVotePolicyForm.create_form(data={"project_name": project.name})

    if await form.validate_on_submit():
        return await add_voting_policy(web_session, form)

    # For GET requests, show the form
    return await quart.render_template(
        "vote-policy-add.html",
        asf_id=web_session.uid,
        project=project,
        form=form,
    )
