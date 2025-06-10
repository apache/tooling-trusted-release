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
import atr.template as template
import atr.user as user
import atr.util as util


class AddFormProtocol(Protocol):
    project_name: wtforms.HiddenField
    derived_project_name: wtforms.StringField
    submit: wtforms.SubmitField


class ProjectMetadataForm(util.QuartFormTyped):
    project_name = wtforms.HiddenField(validators=[wtforms.validators.InputRequired()])
    category_to_add = wtforms.StringField("New category name")
    language_to_add = wtforms.StringField("New language name")


class ReleasePolicyForm(util.QuartFormTyped):
    """
    A Form to create or edit a ReleasePolicy.

    TODO: Currently only a single mailto_address is supported.
          see: https://stackoverflow.com/questions/49066046/append-entry-to-fieldlist-with-flask-wtforms-using-ajax
    """

    project_name = wtforms.HiddenField("project_name")
    default_start_vote_template_hash = wtforms.HiddenField()
    default_announce_release_template_hash = wtforms.HiddenField()
    default_min_hours_value_at_render = wtforms.HiddenField()

    mailto_addresses = wtforms.FieldList(
        wtforms.StringField(
            "Email",
            validators=[
                wtforms.validators.InputRequired("Please provide a valid email address"),
                wtforms.validators.Email(),
            ],
            render_kw={"size": 30, "placeholder": "E.g. dev@project.apache.org"},
            description="Note: This field determines where vote and finished release announcement emails are sent."
            " You can set this value to your own mailing list, but ATR will currently only let you send to"
            " user-tests@tooling.apache.org.",
        ),
        min_entries=1,
    )
    min_hours = wtforms.IntegerField(
        "Minimum voting period",
        validators=[
            wtforms.validators.InputRequired("Please provide a minimum voting period"),
            util.validate_vote_duration,
        ],
        default=72,
        description="The minimum time to run the vote, in hours. Must be 0 or between 72 and 144 inclusive."
        " If 0, then wait until 3 +1 votes and more +1 than -1.",
    )
    manual_vote = wtforms.BooleanField(
        "Manual voting process",
        description="If this is set then the vote will be completely manual and following policy is ignored.",
    )
    release_checklist = wtforms.StringField(
        "Release checklist",
        widget=wtforms.widgets.TextArea(),
        render_kw={"rows": 10},
        description="Markdown text describing how to test release candidates.",
    )
    start_vote_template = wtforms.StringField(
        "Start vote template",
        widget=wtforms.widgets.TextArea(),
        render_kw={"rows": 10},
        description="Email template for messages to start a vote on a release.",
    )
    announce_release_template = wtforms.StringField(
        "Announce release template",
        widget=wtforms.widgets.TextArea(),
        render_kw={"rows": 10},
        description="Email template for messages to announce a finished release.",
    )
    pause_for_rm = wtforms.BooleanField(
        "Pause for RM", description="If enabled, RM can confirm manually if the vote has passed."
    )

    submit_policy = wtforms.SubmitField("Save")


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
            description="The desired suffix for the full project name.",
        )
        submit = wtforms.SubmitField("Add project")

    form = await AddForm.create_form(data={"project_name": project_name})

    if await form.validate_on_submit():
        return await _project_add(form, session.uid)

    return await template.render("project-add-project.html", form=form, project_name=project.display_name)


@routes.committer("/project/delete", methods=["POST"])
async def delete(session: routes.CommitterSession) -> response.Response:
    """Delete a project created by the user."""
    # TODO: This is not truly empty, so make a form object for this
    await util.validate_empty_form()
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
        return await template.render("projects.html", projects=projects, empty_form=await util.EmptyForm.create_form())


@routes.committer("/project/select")
async def select(session: routes.CommitterSession) -> str:
    """Select a project to work on."""
    user_projects = []
    if session.uid:
        async with db.session() as data:
            # TODO: Move this filtering logic somewhere else
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

    return await template.render("project-select.html", user_projects=user_projects)


@routes.committer("/projects/<name>", methods=["GET", "POST"])
async def view(session: routes.CommitterSession, name: str) -> response.Response | str:
    policy_form = None
    metadata_form = None
    can_edit = False

    async with db.session() as data:
        project = await data.project(
            name=name, _committee=True, _committee_public_signing_keys=True, _release_policy=True
        ).demand(http.client.HTTPException(404))

        is_committee_member = project.committee and (user.is_committee_member(project.committee, session.uid))
        is_privileged = user.is_admin(session.uid)
        can_edit = is_committee_member or is_privileged

        if can_edit and (quart.request.method == "POST"):
            form_data = await quart.request.form
            if "submit_metadata" in form_data:
                edited_metadata, metadata_form = await _metadata_edit(data, project, form_data)
                if edited_metadata is True:
                    return quart.redirect(util.as_url(view, name=project.name))
            elif "submit_policy" in form_data:
                edited_policy, policy_form = await _policy_edit(data, project, form_data)
                if edited_policy:
                    return quart.redirect(util.as_url(view, name=project.name))

        if metadata_form is None:
            metadata_form = await ProjectMetadataForm.create_form(data={"project_name": project.name})
        if policy_form is None:
            policy_form = await _policy_form_create(project)

    return await template.render(
        "project-view.html",
        project=project,
        algorithms=routes.algorithms,
        candidate_drafts=await project.candidate_drafts,
        candidates=await project.candidates,
        previews=await project.previews,
        full_releases=await project.full_releases,
        number_of_release_files=util.number_of_release_files,
        now=datetime.datetime.now(datetime.UTC),
        empty_form=await util.EmptyForm.create_form(),
        policy_form=policy_form,
        can_edit=can_edit,
        metadata_form=metadata_form,
    )


async def _metadata_category_edit(
    metadata_form: ProjectMetadataForm,
    project: models.Project,
    action_type: str,
    action_value: str,
    current_categories: list[str],
    current_languages: list[str],
) -> bool:
    # TODO: Add error handling
    # Also this only just squeaks by the complexity checker
    modified = False
    if (action_type == "add_category") and metadata_form.category_to_add.data:
        new_cat = metadata_form.category_to_add.data.strip()
        if new_cat and (new_cat not in current_categories):
            if ":" in new_cat:
                raise ValueError(f"Category '{new_cat}' contains a colon")
            current_categories.append(new_cat)
            current_categories.sort()
            project.category = ", ".join(current_categories)
            await quart.flash(f"Category '{new_cat}' added.", "success")
            modified = True
    elif (action_type == "remove_category") and action_value and (action_value in current_categories):
        current_categories.remove(action_value)
        project.category = ", ".join(current_categories)
        await quart.flash(f"Category '{action_value}' removed.", "success")
        modified = True
    elif (action_type == "add_language") and metadata_form.language_to_add.data:
        new_lang = metadata_form.language_to_add.data.strip()
        if new_lang and (new_lang not in current_languages):
            if ":" in new_lang:
                raise ValueError(f"Language '{new_lang}' contains a colon")
            current_languages.append(new_lang)
            current_languages.sort()
            project.programming_languages = ", ".join(current_languages)
            await quart.flash(f"Language '{new_lang}' added.", "success")
            modified = True
    elif (action_type == "remove_language") and action_value and (action_value in current_languages):
        current_languages.remove(action_value)
        project.programming_languages = ", ".join(current_languages)
        await quart.flash(f"Language '{action_value}' removed.", "success")
        modified = True
    return modified


async def _metadata_edit(
    data: db.Session, project: models.Project, form_data: dict[str, str]
) -> tuple[bool, ProjectMetadataForm]:
    metadata_form = await ProjectMetadataForm.create_form(data=form_data)

    if await metadata_form.validate_on_submit():
        current_categories = (
            [category.strip() for category in (project.category or "").split(",") if category.strip()]
            if project.category
            else []
        )
        current_languages = (
            [language.strip() for language in (project.programming_languages or "").split(",") if language.strip()]
            if project.programming_languages
            else []
        )

        form_data = await quart.request.form
        action_full = form_data.get("action", "")
        action_type = ""
        action_value = ""
        if ":" in action_full:
            action_type, action_value = action_full.split(":", 1)
        else:
            action_type = action_full

        modified = await _metadata_category_edit(
            metadata_form, project, action_type, action_value, current_categories, current_languages
        )

        if modified:
            if project.category == "":
                project.category = None
            if project.programming_languages == "":
                project.programming_languages = None
            await data.commit()
            return True, metadata_form
    return False, metadata_form


async def _policy_edit(
    data: db.Session, project: models.Project, form_data: dict[str, str]
) -> tuple[bool, ReleasePolicyForm]:
    policy_form = await ReleasePolicyForm.create_form(data=form_data)
    if await policy_form.validate_on_submit():
        release_policy = project.release_policy
        if release_policy is None:
            release_policy = models.ReleasePolicy(project=project)
            project.release_policy = release_policy
            data.add(release_policy)

        release_policy.mailto_addresses = [util.unwrap(policy_form.mailto_addresses.entries[0].data)]
        release_policy.manual_vote = util.unwrap(policy_form.manual_vote.data)
        release_policy.release_checklist = util.unwrap(policy_form.release_checklist.data)
        _set_default_fields(policy_form, project, release_policy)

        release_policy.pause_for_rm = util.unwrap(policy_form.pause_for_rm.data)
        await data.commit()
        await quart.flash("Release policy updated successfully.", "success")
        return True, policy_form
    return False, policy_form


async def _policy_form_create(project: models.Project) -> ReleasePolicyForm:
    policy_form = await ReleasePolicyForm.create_form()
    policy_form.project_name.data = project.name
    if project.policy_mailto_addresses:
        policy_form.mailto_addresses.entries[0].data = project.policy_mailto_addresses[0]
    else:
        policy_form.mailto_addresses.entries[0].data = f"dev@{project.name}.apache.org"
    policy_form.min_hours.data = project.policy_min_hours
    policy_form.manual_vote.data = project.policy_manual_vote
    policy_form.release_checklist.data = project.policy_release_checklist
    policy_form.start_vote_template.data = project.policy_start_vote_template
    policy_form.announce_release_template.data = project.policy_announce_release_template
    policy_form.pause_for_rm.data = project.policy_pause_for_rm

    # Set the hashes and value of the current defaults
    policy_form.default_start_vote_template_hash.data = util.compute_sha3_256(
        project.policy_start_vote_default.encode()
    )
    policy_form.default_announce_release_template_hash.data = util.compute_sha3_256(
        project.policy_announce_release_default.encode()
    )
    policy_form.default_min_hours_value_at_render.data = str(project.policy_default_min_hours)
    return policy_form


async def _project_add(form: AddFormProtocol, asf_id: str) -> response.Response:
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
        base_name = base_project.display_name
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
            is_retired=base_project.is_retired,
            super_project_name=base_project.name,
            description=base_project.description,
            category=base_project.category,
            programming_languages=base_project.programming_languages,
            committee_name=base_project.committee_name,
            release_policy_id=base_project.release_policy_id,
            created=datetime.datetime.now(datetime.UTC),
            created_by=asf_id,
        )

        data.add(project)
        await data.commit()

    return quart.redirect(util.as_url(view, name=new_project_label))


def _set_default_fields(form: ReleasePolicyForm, project: models.Project, release_policy: models.ReleasePolicy) -> None:
    # Handle start_vote_template
    submitted_start_template = str(util.unwrap(form.start_vote_template.data))
    submitted_start_template = submitted_start_template.replace("\r\n", "\n")
    rendered_default_start_hash = str(util.unwrap(form.default_start_vote_template_hash.data))
    current_default_start_text = project.policy_start_vote_default
    current_default_start_hash = util.compute_sha3_256(current_default_start_text.encode())
    submitted_start_hash = util.compute_sha3_256(submitted_start_template.encode())

    if (submitted_start_hash == rendered_default_start_hash) or (submitted_start_hash == current_default_start_hash):
        release_policy.start_vote_template = ""
    else:
        release_policy.start_vote_template = submitted_start_template

    # Handle announce_release_template
    submitted_announce_template = str(util.unwrap(form.announce_release_template.data))
    submitted_announce_template = submitted_announce_template.replace("\r\n", "\n")
    rendered_default_announce_hash = str(util.unwrap(form.default_announce_release_template_hash.data))
    current_default_announce_text = project.policy_announce_release_default
    current_default_announce_hash = util.compute_sha3_256(current_default_announce_text.encode())
    submitted_announce_hash = util.compute_sha3_256(submitted_announce_template.encode())

    if (submitted_announce_hash == rendered_default_announce_hash) or (
        submitted_announce_hash == current_default_announce_hash
    ):
        release_policy.announce_release_template = ""
    else:
        release_policy.announce_release_template = submitted_announce_template

    # Handle min_hours
    submitted_min_hours = int(util.unwrap(form.min_hours.data) or 0)
    default_value_seen_on_page_min_hours = int(util.unwrap(form.default_min_hours_value_at_render.data))
    current_system_default_min_hours = project.policy_default_min_hours

    if (
        submitted_min_hours == default_value_seen_on_page_min_hours
        or submitted_min_hours == current_system_default_min_hours
    ):
        release_policy.min_hours = None
    else:
        release_policy.min_hours = submitted_min_hours
