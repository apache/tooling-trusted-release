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

import datetime
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
    project_name: wtforms.HiddenField
    derived_project_name: wtforms.StringField
    submit: wtforms.SubmitField


class VotePolicyForm(util.QuartFormTyped):
    """
    A Form to create or edit a VotePolicy.

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
        "Minimum voting period:",
        validators=[
            wtforms.validators.InputRequired("Please provide a minimum voting period"),
            util.validate_vote_duration,
        ],
        default=72,
    )
    manual_vote = wtforms.BooleanField("Voting process:")
    release_checklist = wtforms.StringField("Release checklist:", widget=wtforms.widgets.TextArea())
    pause_for_rm = wtforms.BooleanField("Pause for RM:")

    submit = wtforms.SubmitField("Save")


@routes.committer("/project/add/<project_name>", methods=["GET", "POST"])
async def add_project(session: routes.CommitterSession, project_name: str) -> response.Response | str:
    await session.check_access(project_name)

    async with db.session() as data:
        project = await data.project(name=project_name).demand(
            base.ASFQuartException(f"Project {project_name} not found", errorcode=404)
        )

    class AddForm(util.QuartFormTyped):
        project_name = wtforms.HiddenField("project_name")
        derived_project_name = wtforms.StringField(
            "Derived project",
            validators=[
                wtforms.validators.InputRequired("Please provide a derived project name."),
                wtforms.validators.Length(min=1, max=100),
            ],
        )
        submit = wtforms.SubmitField("Add project")

    form = await AddForm.create_form(data={"project_name": project_name})

    if await form.validate_on_submit():
        return await _add_project(form, session.uid)

    return await quart.render_template("project-add-project.html", form=form, project_name=project.display_name)


@routes.committer("/project/delete", methods=["POST"])
async def delete(session: routes.CommitterSession) -> response.Response:
    """Delete a project created by the user."""
    form_data = await quart.request.form
    project_name = form_data.get("project_name")
    if not project_name:
        return await session.redirect(projects, error="Missing project name for deletion.")

    async with db.session() as data:
        project = await data.project(name=project_name, _releases=True, _distribution_channels=True).get()

        if not project:
            return await session.redirect(projects, error=f"Project '{project_name}' not found.")

        # Check for ownership or admin status
        is_owner = project.created_by == session.uid
        is_privileged = util.is_user_viewing_as_admin(session.uid)

        if not (is_owner or is_privileged):
            return await session.redirect(
                projects, error=f"You do not have permission to delete project '{project_name}'."
            )

        # Prevent deletion if there are associated releases or channels
        if project.releases:
            return await session.redirect(
                projects, error=f"Cannot delete project '{project_name}' because it has associated releases."
            )
        if project.distribution_channels:
            return await session.redirect(
                projects,
                error=f"Cannot delete project '{project_name}' because it has associated distribution channels.",
            )

        await data.delete(project)
        await data.commit()

    return await session.redirect(projects, success=f"Project '{project_name}' deleted successfully.")


@routes.public("/projects")
async def projects() -> str:
    """Main project directory page."""
    async with db.session() as data:
        projects = await data.project(_committee=True).order_by(models.Project.full_name).all()
        return await quart.render_template("projects.html", projects=projects)


@routes.committer("/project/select")
async def select(session: routes.CommitterSession) -> str:
    """Select a project to work on."""
    user_projects = []
    if session.uid:
        # TODO: Move this filtering logic somewhere else
        async with db.session() as data:
            all_projects = await data.project(_committee=True).all()
            user_projects = [
                p
                for p in all_projects
                if p.committee
                and (
                    (session.uid in p.committee.committee_members)
                    or (session.uid in p.committee.committers)
                    or (session.uid in p.committee.release_managers)
                )
            ]
            user_projects.sort(key=lambda p: p.display_name)

    return await quart.render_template("project-select.html", user_projects=user_projects)


@routes.public("/projects/<name>")
async def view(name: str) -> str:
    async with db.session() as data:
        project = await data.project(name=name, _committee_public_signing_keys=True, _vote_policy=True).demand(
            http.client.HTTPException(404)
        )
        return await quart.render_template(
            "project-view.html",
            project=project,
            algorithms=routes.algorithms,
            candidate_drafts=await project.candidate_drafts,
            candidates=await project.candidates,
            previews=await project.previews,
            full_releases=await project.full_releases,
            number_of_release_files=util.number_of_release_files,
            now=datetime.datetime.now(datetime.UTC),
        )


@routes.committer("/projects/<project_name>/vote-policy/add", methods=["GET", "POST"])
async def vote_policy_add(session: routes.CommitterSession, project_name: str) -> response.Response | str:
    await session.check_access(project_name)

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
    await session.check_access(project_name)

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


async def _add_project(form: AddFormProtocol, asf_id: str) -> response.Response:
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
            # This should not happen
            raise RuntimeError(f"Base project {base_project_name} not found")
        if base_project.super_project_name:
            await quart.flash(f"Project {base_project.name} is already a derived project", "error")
            return quart.redirect(util.as_url(add_project, project_name=base_project.name))

        # Construct the new label
        derived_label = _generate_label(derived_project_name)
        if not derived_label:
            await quart.flash("Derived project name must contain valid characters for label generation", "error")
            return quart.redirect(util.as_url(add_project, project_name=base_project.name))
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
            await quart.flash(f"Derived project {new_project_label} already exists", "error")
            return quart.redirect(util.as_url(add_project, project_name=base_project.name))

        project = models.Project(
            name=new_project_label,
            full_name=new_project_full_name,
            is_podling=base_project.is_podling,
            is_retired=base_project.is_retired,
            super_project_name=base_project.name,
            description=base_project.description,
            category=base_project.category,
            programming_languages=base_project.programming_languages,
            committee_name=base_project.committee_name,
            vote_policy_id=base_project.vote_policy_id,
            created=datetime.datetime.now(datetime.UTC),
            created_by=asf_id,
        )

        data.add(project)
        await data.commit()

    return quart.redirect(util.as_url(view, name=new_project_label))


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
