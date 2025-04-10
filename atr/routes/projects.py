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
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.user as user
import atr.util as util


@routes.committer("/project/add", methods=["GET", "POST"])
async def add(session: routes.CommitterSession) -> response.Response | str:
    raise NotImplementedError("Not implemented")


@routes.public("/projects")
async def directory() -> str:
    """Main project directory page."""
    async with db.session() as data:
        projects = await data.project(_committee=True).order_by(models.Project.full_name).all()
        return await quart.render_template("project-directory.html", projects=projects)


@routes.public("/projects/<name>")
async def view(name: str) -> str:
    async with db.session() as data:
        project = await data.project(name=name, _committee_public_signing_keys=True, _vote_policy=True).demand(
            http.client.HTTPException(404)
        )
        return await quart.render_template("project-view.html", project=project, algorithms=routes.algorithms)


class VotePolicyForm(util.QuartFormTyped):
    """
    A Form to create/edit a VotePolicy.

    TODO: Currently only a single mailto_address is supported.
          see: https://stackoverflow.com/questions/49066046/append-entry-to-fieldlist-with-flask-wtforms-using-ajax
    """

    project_name = wtforms.HiddenField("project_name")
    mailto_addresses = wtforms.FieldList(
        wtforms.StringField(
            "Email",
            validators=[
                wtforms.validators.InputRequired("Please provide a valid email address"),
                wtforms.validators.Email(),
            ],
        ),
        min_entries=1,
    )
    min_hours = wtforms.IntegerField(
        "Minimum Voting Period:",
        validators=[
            wtforms.validators.NumberRange(min=0, max=144, message="Voting period must be between 0h and 144h")
        ],
        default=72,
    )
    manual_vote = wtforms.BooleanField("Voting Process:")
    release_checklist = wtforms.StringField("Release Checklist:", widget=wtforms.widgets.TextArea())
    pause_for_rm = wtforms.BooleanField("Pause for RM:")

    submit = wtforms.SubmitField("Save")


@routes.committer("/projects/<project_name>/vote-policy/add", methods=["GET", "POST"])
async def vote_policy_add(session: routes.CommitterSession, project_name: str) -> response.Response | str:
    uid = await util.get_asf_id_or_die()

    async with db.session() as data:
        project = await data.project(name=project_name, _committee=True, _vote_policy=True).demand(
            base.ASFQuartException(f"Project {project_name} not found", errorcode=404)
        )

        if not (user.is_committee_member(project.committee, uid) or user.is_admin(uid)):
            raise base.ASFQuartException(
                f"You must be a committee member of {project.display_name} to submit a voting policy", errorcode=403
            )

        form = await VotePolicyForm.create_form(data={"project_name": project.name})

        if form.mailto_addresses.entries[0].data is None:
            form.mailto_addresses.entries[0].data = f"dev@{util.unwrap(project.committee).name}.apache.org"

        if await form.validate_on_submit():
            return await _add_voting_policy(project, form, data)

    return await quart.render_template(
        "vote-policy-add.html",
        asf_id=uid,
        project=project,
        form=form,
    )


@routes.committer("/projects/<project_name>/vote-policy/edit", methods=["GET", "POST"])
async def vote_policy_edit(session: routes.CommitterSession, project_name: str) -> response.Response | str:
    uid = await util.get_asf_id_or_die()

    async with db.session() as data:
        project = await data.project(name=project_name, _committee=True, _vote_policy=True).demand(
            base.ASFQuartException(f"Project {project_name} not found", errorcode=404)
        )

        if project.vote_policy is None:
            base.ASFQuartException(f"Vote Policy for project {project_name} does not exist", errorcode=404)

        if not (user.is_committee_member(project.committee, uid) or user.is_admin(uid)):
            raise base.ASFQuartException(
                f"You must be a committee member of {project.display_name} to submit a voting policy", errorcode=403
            )

        form = await VotePolicyForm.create_form()

        # fill data
        if quart.request.method == "GET":
            form.process(obj=project.vote_policy)
            form.project_name.data = project.name

        if await form.validate_on_submit():
            return await _edit_voting_policy(util.unwrap(project.vote_policy), form, data)

    # For GET requests, show the form
    return await quart.render_template(
        "vote-policy-edit.html",
        asf_id=uid,
        project=project,
        form=form,
    )


async def _add_voting_policy(project: models.Project, form: VotePolicyForm, data: db.Session) -> response.Response:
    project_name = str(form.project_name.data)

    vote_policy = models.VotePolicy(
        mailto_addresses=[util.unwrap(form.mailto_addresses.entries[0].data)],
        manual_vote=form.manual_vote.data,
        min_hours=util.unwrap(form.min_hours.data),
        release_checklist=util.unwrap(form.release_checklist.data),
        pause_for_rm=form.pause_for_rm.data,
    )

    vote_policy.project = project
    data.add(vote_policy)
    await data.commit()

    return quart.redirect(util.as_url(view, name=project_name))


async def _edit_voting_policy(
    vote_policy: models.VotePolicy, form: VotePolicyForm, data: db.Session
) -> response.Response:
    project_name = str(form.project_name.data)

    vote_policy.mailto_addresses = [util.unwrap(form.mailto_addresses.entries[0].data)]
    vote_policy.manual_vote = form.manual_vote.data
    vote_policy.min_hours = util.unwrap(form.min_hours.data)
    vote_policy.release_checklist = util.unwrap(form.release_checklist.data)
    vote_policy.pause_for_rm = form.pause_for_rm.data
    await data.commit()

    return quart.redirect(util.as_url(view, name=project_name))
