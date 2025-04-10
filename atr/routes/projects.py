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
import re
from typing import Protocol

import asfquart.base as base
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.user as user
import atr.util as util


class AddFormProtocol(Protocol):
    project_name: wtforms.SelectField
    derived_project_name: wtforms.StringField
    submit: wtforms.SubmitField


@routes.committer("/project/add", methods=["GET", "POST"])
async def add(session: routes.CommitterSession) -> response.Response | str:
    def long_name(project: models.Project) -> str:
        if project.full_name:
            return project.full_name
        return project.name

    user_projects = await session.user_projects

    class AddForm(util.QuartFormTyped):
        project_name = wtforms.SelectField("Project", choices=[(p.name, long_name(p)) for p in user_projects])
        derived_project_name = wtforms.StringField(
            "Derived project",
            validators=[
                wtforms.validators.InputRequired("Please provide a derived project name."),
                wtforms.validators.Length(min=1, max=100),
            ],
        )
        submit = wtforms.SubmitField("Add derived project")

    form = await AddForm.create_form()

    if await form.validate_on_submit():
        return await _add_project(form)

    return await quart.render_template("project-add.html", form=form)


async def _add_project(form: AddFormProtocol) -> response.Response:
    base_project_name = str(form.project_name.data)
    derived_project_name = str(form.derived_project_name.data).strip()

    def _generate_label(text: str) -> str:
        # TODO: We should probably add long name validation
        text = text.lower()
        text = re.sub(r" +", "-", text)
        text = re.sub(r"[^a-z0-9-]", "", text)
        return text

    async with db.session() as data:
        # Get the base project to derive from
        base_project = await data.project(name=base_project_name).get()
        if not base_project:
            # This should not happen, assuming that the dropdown is populated correctly
            raise routes.FlashError(f"Base project {base_project_name} not found")

        # Construct the new label
        derived_label = _generate_label(derived_project_name)
        if not derived_label:
            raise routes.FlashError("Derived project name must contain valid characters for label generation")
        new_project_label = f"{base_project.name}-{derived_label}"

        # Construct the new full name
        # We ensure that parenthesised suffixes like "(Incubating)" are preserved
        base_name = base_project.full_name or base_project.name
        match = re.match(r"^(.*?) *(\(.*\))?$", base_name)
        if match:
            main_part = match.group(1).strip()
            suffix_part = match.group(2)
        else:
            main_part = base_name.strip()
            suffix_part = None

        if suffix_part:
            new_project_full_name = f"{main_part} {derived_project_name} {suffix_part}"
        else:
            new_project_full_name = f"{main_part} {derived_project_name}"
        new_project_full_name = re.sub(r"  +", " ", new_project_full_name).strip()

        # Check whether the derived project already exists by its constructed label
        if await data.project(name=new_project_label).get():
            raise routes.FlashError(f"Derived project {new_project_label} already exists")

        project = models.Project(
            name=new_project_label,
            full_name=new_project_full_name,
            is_podling=base_project.is_podling,
            is_retired=base_project.is_retired,
            description=base_project.description,
            category=base_project.category,
            programming_languages=base_project.programming_languages,
            committee_id=base_project.committee_id,
            vote_policy_id=base_project.vote_policy_id,
            # TODO: Add "created" and "created_by" to models.Project perhaps?
        )

        data.add(project)
        await data.commit()

    return quart.redirect(util.as_url(view, name=new_project_label))


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
