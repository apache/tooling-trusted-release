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

import datetime
import http.client
import re
from typing import TYPE_CHECKING, Any

import asfquart.base as base
import quart

import atr.db as db
import atr.db.interaction as interaction
import atr.forms as forms
import atr.log as log
import atr.models.policy as policy
import atr.models.sql as sql
import atr.registry as registry
import atr.shared as shared
import atr.storage as storage
import atr.template as template
import atr.user as user
import atr.util as util
import atr.web as web

if TYPE_CHECKING:
    import werkzeug.wrappers.response as response


class AddForm(forms.Typed):
    committee_name = forms.hidden()
    display_name = forms.string("Display name")
    label = forms.string("Label")
    submit = forms.submit("Add project")


class ProjectMetadataForm(forms.Typed):
    project_name = forms.hidden()
    category_to_add = forms.optional("New category name")
    language_to_add = forms.optional("New language name")


class ReleasePolicyForm(forms.Typed):
    """
    A Form to create or edit a ReleasePolicy.

    TODO: Currently only a single mailto_address is supported.
          see: https://stackoverflow.com/questions/49066046/append-entry-to-fieldlist-with-flask-wtforms-using-ajax
    """

    project_name = forms.hidden()

    # Compose section
    source_artifact_paths = forms.textarea(
        "Source artifact paths",
        optional=True,
        rows=5,
        description="Paths to source artifacts to be included in the release.",
    )
    binary_artifact_paths = forms.textarea(
        "Binary artifact paths",
        optional=True,
        rows=5,
        description="Paths to binary artifacts to be included in the release.",
    )
    github_repository_name = forms.optional(
        "GitHub repository name",
        description="The name of the GitHub repository to use for the release, excluding the apache/ prefix.",
    )
    github_compose_workflow_path = forms.textarea(
        "GitHub compose workflow paths",
        optional=True,
        rows=5,
        description="The full paths to the GitHub workflows to use for the release,"
        " including the .github/workflows/ prefix.",
    )
    strict_checking = forms.boolean(
        "Strict checking", description="If enabled, then the release cannot be voted upon unless all checks pass."
    )

    # Vote section
    github_vote_workflow_path = forms.textarea(
        "GitHub vote workflow paths",
        optional=True,
        rows=5,
        description="The full paths to the GitHub workflows to use for the release,"
        " including the .github/workflows/ prefix.",
    )
    mailto_addresses = forms.string(
        "Email",
        validators=[forms.REQUIRED, forms.EMAIL],
        placeholder="E.g. dev@project.apache.org",
        description=f"The mailing list where vote emails are sent. This is usually"
        "your dev list. ATR will currently only send test announcement emails to"
        f"{util.USER_TESTS_ADDRESS}.",
    )
    manual_vote = forms.boolean(
        "Manual voting process",
        description="If this is set then the vote will be completely manual and following policy is ignored.",
    )
    default_min_hours_value_at_render = forms.hidden()
    min_hours = forms.integer(
        "Minimum voting period",
        validators=[util.validate_vote_duration],
        default=72,
        description="The minimum time to run the vote, in hours. Must be 0 or between 72 and 144 inclusive."
        " If 0, then wait until 3 +1 votes and more +1 than -1.",
    )
    pause_for_rm = forms.boolean(
        "Pause for RM", description="If enabled, RM can confirm manually if the vote has passed."
    )
    release_checklist = forms.textarea(
        "Release checklist",
        optional=True,
        rows=10,
        description="Markdown text describing how to test release candidates.",
    )
    default_start_vote_template_hash = forms.hidden()
    start_vote_template = forms.textarea(
        "Start vote template",
        optional=True,
        rows=10,
        description="Email template for messages to start a vote on a release.",
    )

    # Finish section
    default_announce_release_template_hash = forms.hidden()
    announce_release_template = forms.textarea(
        "Announce release template",
        optional=True,
        rows=10,
        description="Email template for messages to announce a finished release.",
    )
    github_finish_workflow_path = forms.textarea(
        "GitHub finish workflow paths",
        optional=True,
        rows=5,
        description="The full paths to the GitHub workflows to use for the release,"
        " including the .github/workflows/ prefix.",
    )
    preserve_download_files = forms.boolean(
        "Preserve download files",
        description="If enabled, existing download files will not be overwritten.",
    )

    submit_policy = forms.submit("Save")

    async def validate(self, extra_validators: dict[str, Any] | None = None) -> bool:  # noqa: C901
        await super().validate(extra_validators=extra_validators)

        if self.manual_vote.data:
            for field_name in (
                "mailto_addresses",
                "min_hours",
                "pause_for_rm",
                "release_checklist",
                "start_vote_template",
            ):
                field = getattr(self, field_name, None)
                if field is not None:
                    forms.clear_errors(field)
                self.errors.pop(field_name, None)

        if self.manual_vote.data and self.strict_checking.data:
            msg = "Manual voting process and strict checking cannot be enabled simultaneously."
            forms.error(self.manual_vote, msg)
            forms.error(self.strict_checking, msg)

        github_repository_name = (self.github_repository_name.data or "").strip()
        compose_raw = self.github_compose_workflow_path.data or ""
        vote_raw = self.github_vote_workflow_path.data or ""
        finish_raw = self.github_finish_workflow_path.data or ""
        compose = [p.strip() for p in compose_raw.split("\n") if p.strip()]
        vote = [p.strip() for p in vote_raw.split("\n") if p.strip()]
        finish = [p.strip() for p in finish_raw.split("\n") if p.strip()]

        any_path = bool(compose or vote or finish)
        if any_path and (not github_repository_name):
            forms.error(
                self.github_repository_name,
                "GitHub repository name is required when any workflow path is set.",
            )

        if github_repository_name and ("/" in github_repository_name):
            forms.error(self.github_repository_name, "GitHub repository name must not contain a slash.")

        if compose:
            for p in compose:
                if not p.startswith(".github/workflows/"):
                    forms.error(
                        self.github_compose_workflow_path,
                        "GitHub workflow paths must start with '.github/workflows/'.",
                    )
                    break
        if vote:
            for p in vote:
                if not p.startswith(".github/workflows/"):
                    forms.error(
                        self.github_vote_workflow_path,
                        "GitHub workflow paths must start with '.github/workflows/'.",
                    )
                    break
        if finish:
            for p in finish:
                if not p.startswith(".github/workflows/"):
                    forms.error(
                        self.github_finish_workflow_path,
                        "GitHub workflow paths must start with '.github/workflows/'.",
                    )
                    break

        return not self.errors


async def add_project(session: web.Committer, committee_name: str) -> response.Response | str:
    await session.check_access_committee(committee_name)

    async with db.session() as data:
        committee = await data.committee(name=committee_name).demand(
            base.ASFQuartException(f"Committee {committee_name} not found", errorcode=404)
        )

    form = await AddForm.create_form(data={"committee_name": committee_name})
    form.display_name.description = f"""\
For example, "Apache {committee.display_name}" or "Apache {committee.display_name} Components".
You must start with "Apache " and you must use title case.
"""
    form.label.description = f"""\
For example, "{committee.name}" or "{committee.name}-components".
You must start with your committee label, and you must use lower case.
"""

    if await form.validate_on_submit():
        return await _project_add(form, session)

    return await template.render("project-add-project.html", form=form, committee_name=committee.display_name)


async def view(session: web.Committer, name: str) -> response.Response | str:
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
            edited_metadata, metadata_form = await _metadata_edit(session, project, form_data)
            if edited_metadata is True:
                return quart.redirect(util.as_url(view, name=project.name))
        elif "submit_policy" in form_data:
            policy_form = await ReleasePolicyForm.create_form(data=form_data)
            if await policy_form.validate_on_submit():
                policy_data = policy.ReleasePolicyData.model_validate(policy_form.data)
                async with storage.write(session) as write:
                    wacm = await write.as_project_committee_member(project.name)
                    try:
                        await wacm.policy.edit(project, policy_data)
                    except storage.AccessError as e:
                        return await session.redirect(view, name=project.name, error=f"Error editing policy: {e}")
                    return quart.redirect(util.as_url(view, name=project.name))
            else:
                log.info(f"policy_form.errors: {policy_form.errors}")
        else:
            log.info(f"Unknown form data: {form_data}")

    if metadata_form is None:
        metadata_form = await ProjectMetadataForm.create_form(data={"project_name": project.name})
    if policy_form is None:
        policy_form = await _policy_form_create(project)
    candidate_drafts = await interaction.candidate_drafts(project)
    candidates = await interaction.candidates(project)
    previews = await interaction.previews(project)
    full_releases = await interaction.full_releases(project)

    return await template.render(
        "project-view.html",
        project=project,
        algorithms=shared.algorithms,
        candidate_drafts=candidate_drafts,
        candidates=candidates,
        previews=previews,
        full_releases=full_releases,
        number_of_release_files=util.number_of_release_files,
        now=datetime.datetime.now(datetime.UTC),
        empty_form=await forms.Empty.create_form(),
        policy_form=policy_form,
        can_edit=can_edit,
        metadata_form=metadata_form,
        forbidden_categories=registry.FORBIDDEN_PROJECT_CATEGORIES,
    )


async def _metadata_category_add(
    wacm: storage.WriteAsCommitteeMember, project: sql.Project, category_to_add: str
) -> bool:
    modified = False
    try:
        modified = await wacm.project.category_add(project, category_to_add.strip())
    except storage.AccessError as e:
        await quart.flash(f"Error adding category: {e}", "error")
    if modified:
        await quart.flash(f"Category '{category_to_add}' added.", "success")
    else:
        await quart.flash(f"Category '{category_to_add}' already exists.", "error")
    return modified


async def _metadata_category_remove(
    wacm: storage.WriteAsCommitteeMember, project: sql.Project, action_value: str
) -> bool:
    modified = False
    try:
        modified = await wacm.project.category_remove(project, action_value)
    except storage.AccessError as e:
        await quart.flash(f"Error removing category: {e}", "error")
    if modified:
        await quart.flash(f"Category '{action_value}' removed.", "success")
    else:
        await quart.flash(f"Category '{action_value}' does not exist.", "error")
    return modified


async def _metadata_edit(
    session: web.Committer, project: sql.Project, form_data: dict[str, str]
) -> tuple[bool, ProjectMetadataForm]:
    metadata_form = await ProjectMetadataForm.create_form(data=form_data)

    validated = await metadata_form.validate_on_submit()
    if not validated:
        return False, metadata_form

    form_data = await quart.request.form
    action_full = form_data.get("action", "")
    action_type = ""
    action_value = ""
    if ":" in action_full:
        action_type, action_value = action_full.split(":", 1)
    else:
        action_type = action_full

    # TODO: Add error handling
    modified = False
    category_to_add = metadata_form.category_to_add.data
    language_to_add = metadata_form.language_to_add.data

    async with storage.write(session) as write:
        wacm = await write.as_project_committee_member(project.name)

        if (action_type == "add_category") and category_to_add:
            modified = await _metadata_category_add(wacm, project, category_to_add)
        elif (action_type == "remove_category") and action_value:
            modified = await _metadata_category_remove(wacm, project, action_value)
        elif (action_type == "add_language") and language_to_add:
            modified = await _metadata_language_add(wacm, project, language_to_add)
        elif (action_type == "remove_language") and action_value:
            modified = await _metadata_language_remove(wacm, project, action_value)

    return modified, metadata_form


async def _metadata_language_add(
    wacm: storage.WriteAsCommitteeMember, project: sql.Project, language_to_add: str
) -> bool:
    modified = False
    try:
        modified = await wacm.project.language_add(project, language_to_add)
    except storage.AccessError as e:
        await quart.flash(f"Error adding language: {e}", "error")
    if modified:
        await quart.flash(f"Language '{language_to_add}' added.", "success")
    else:
        await quart.flash(f"Language '{language_to_add}' already exists.", "error")
    return modified


async def _metadata_language_remove(
    wacm: storage.WriteAsCommitteeMember, project: sql.Project, action_value: str
) -> bool:
    modified = False
    try:
        modified = await wacm.project.language_remove(project, action_value)
    except storage.AccessError as e:
        await quart.flash(f"Error removing language: {e}", "error")
    if modified:
        await quart.flash(f"Language '{action_value}' removed.", "success")
    else:
        await quart.flash(f"Language '{action_value}' does not exist.", "error")
    return modified


async def _policy_form_create(project: sql.Project) -> ReleasePolicyForm:
    # TODO: Use form order for all of these fields
    policy_form = await ReleasePolicyForm.create_form()
    policy_form.project_name.data = project.name
    if project.policy_mailto_addresses:
        policy_form.mailto_addresses.data = project.policy_mailto_addresses[0]
    else:
        policy_form.mailto_addresses.data = f"dev@{project.name}.apache.org"
    policy_form.min_hours.data = project.policy_min_hours
    policy_form.manual_vote.data = project.policy_manual_vote
    policy_form.release_checklist.data = project.policy_release_checklist
    policy_form.start_vote_template.data = project.policy_start_vote_template
    policy_form.announce_release_template.data = project.policy_announce_release_template
    policy_form.binary_artifact_paths.data = "\n".join(project.policy_binary_artifact_paths)
    policy_form.source_artifact_paths.data = "\n".join(project.policy_source_artifact_paths)
    policy_form.pause_for_rm.data = project.policy_pause_for_rm
    policy_form.strict_checking.data = project.policy_strict_checking
    policy_form.github_repository_name.data = project.policy_github_repository_name
    policy_form.github_compose_workflow_path.data = "\n".join(project.policy_github_compose_workflow_path)
    policy_form.github_vote_workflow_path.data = "\n".join(project.policy_github_vote_workflow_path)
    policy_form.github_finish_workflow_path.data = "\n".join(project.policy_github_finish_workflow_path)
    policy_form.preserve_download_files.data = project.policy_preserve_download_files

    # Set the hashes and value of the current defaults
    policy_form.default_start_vote_template_hash.data = util.compute_sha3_256(
        project.policy_start_vote_default.encode()
    )
    policy_form.default_announce_release_template_hash.data = util.compute_sha3_256(
        project.policy_announce_release_default.encode()
    )
    policy_form.default_min_hours_value_at_render.data = str(project.policy_default_min_hours)
    return policy_form


async def _project_add(form: AddForm, session: web.Committer) -> response.Response:
    form_values = await _project_add_validate(form)
    if form_values is None:
        return quart.redirect(util.as_url(add_project, committee_name=form.committee_name.data))
    committee_name, display_name, label = form_values

    async with storage.write(session) as write:
        wacm = await write.as_project_committee_member(committee_name)
        try:
            await wacm.project.create(committee_name, display_name, label)
        except storage.AccessError as e:
            await quart.flash(f"Error adding project: {e}", "error")
            return quart.redirect(util.as_url(add_project, committee_name=committee_name))

    return quart.redirect(util.as_url(view, name=label))


async def _project_add_validate(form: AddForm) -> tuple[str, str, str] | None:
    committee_name = str(form.committee_name.data)
    # Normalise spaces in the display name, then validate
    display_name = str(form.display_name.data).strip()
    display_name = re.sub(r"  +", " ", display_name)
    if not await _project_add_validate_display_name(display_name):
        return None
    # Hidden criterion!
    # $ sqlite3 state/atr.db 'select full_name from project;' | grep -- '[^A-Za-z0-9 ]'
    # Apache .NET Ant Library
    # Apache Oltu - Parent
    # Apache Commons Chain (Dormant)
    # Apache Commons Functor (Dormant)
    # Apache Commons OGNL (Dormant)
    # Apache Commons Proxy (Dormant)
    # Apache Empire-db
    # Apache mod_ftp
    # Apache Lucene.Net
    # Apache mod_perl
    # Apache Xalan for C++ XSLT Processor
    # Apache Xerces for C++ XML Parser
    if not display_name.replace(" ", "").replace(".", "").replace("+", "").isalnum():
        await quart.flash("Display name must be alphanumeric and may include spaces or dots or plus signs", "error")
        return None

    label = str(form.label.data).strip()
    if not (label.startswith(committee_name + "-") or (label == committee_name)):
        await quart.flash(f"Label must start with '{committee_name}-'", "error")
        return None
    if not label.islower():
        await quart.flash("Label must be all lower case", "error")
        return None
    # Hidden criterion!
    if not label.replace("-", "").isalnum():
        await quart.flash("Label must be alphanumeric and may include hyphens", "error")
        return None

    return (committee_name, display_name, label)


async def _project_add_validate_display_name(display_name: str) -> bool:
    # We have three criteria for display names
    must_start_apache = "The first display name word must be 'Apache'."
    must_have_two_words = "The display name must have at least two words."
    must_use_correct_case = "Display name words must be in PascalCase, camelCase, or mod_ case."

    # First criterion, the first word must be "Apache"
    display_name_words = display_name.split(" ")
    if display_name_words[0] != "Apache":
        await quart.flash(must_start_apache, "error")
        return False

    # Second criterion, the display name must have two or more words
    if not display_name_words[1:]:
        await quart.flash(must_have_two_words, "error")
        return False

    # Third criterion, the display name must use the correct case
    allowed_irregular_words = {".NET", "C++", "Empire-db", "Lucene.NET", "for", "jclouds"}
    r_pascal_case = re.compile(r"^([A-Z][0-9a-z]*)+$")
    r_camel_case = re.compile(r"^[a-z]*([A-Z][0-9a-z]*)+$")
    r_mod_case = re.compile(r"^mod(_[0-9a-z]+)+$")
    for display_name_word in display_name_words[1:]:
        if display_name_word in allowed_irregular_words:
            continue
        is_pascal_case = r_pascal_case.match(display_name_word)
        is_camel_case = r_camel_case.match(display_name_word)
        is_mod_case = r_mod_case.match(display_name_word)
        if not (is_pascal_case or is_camel_case or is_mod_case):
            await quart.flash(must_use_correct_case, "error")
            return False
    return True
