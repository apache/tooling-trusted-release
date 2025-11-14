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

import re
from typing import Annotated, Literal

import asfquart.base as base
import pydantic
import quart

import atr.db as db
import atr.form as form
import atr.forms as forms
import atr.get as get
import atr.storage as storage
import atr.template as template
import atr.util as util
import atr.web as web

type COMPOSE = Literal["compose"]
type VOTE = Literal["vote"]
type FINISH = Literal["finish"]
type ADD_CATEGORY = Literal["add_category"]
type REMOVE_CATEGORY = Literal["remove_category"]
type ADD_LANGUAGE = Literal["add_language"]
type REMOVE_LANGUAGE = Literal["remove_language"]
type DELETE_PROJECT = Literal["delete_project"]


class AddForm(forms.Typed):
    committee_name = forms.hidden()
    display_name = forms.string("Display name")
    label = forms.string("Label")
    submit = forms.submit("Add project")


class ComposePolicyForm(form.Form):
    variant: COMPOSE = form.value(COMPOSE)
    project_name: str = form.label("Project name", widget=form.Widget.HIDDEN)
    source_artifact_paths: str = form.label(
        "Source artifact paths",
        "Paths to source artifacts to be included in the release.",
        widget=form.Widget.TEXTAREA,
    )
    binary_artifact_paths: str = form.label(
        "Binary artifact paths",
        "Paths to binary artifacts to be included in the release.",
        widget=form.Widget.TEXTAREA,
    )
    github_repository_name: str = form.label(
        "GitHub repository name",
        "The name of the GitHub repository to use for the release, excluding the apache/ prefix.",
    )
    github_compose_workflow_path: str = form.label(
        "GitHub compose workflow paths",
        "The full paths to the GitHub workflows to use for the release, including the .github/workflows/ prefix.",
        widget=form.Widget.TEXTAREA,
    )
    strict_checking: form.Bool = form.label(
        "Strict checking",
        "If enabled, then the release cannot be voted upon unless all checks pass.",
    )

    @pydantic.model_validator(mode="after")
    def validate_github_fields(self) -> ComposePolicyForm:
        github_repository_name = self.github_repository_name.strip()
        compose_raw = self.github_compose_workflow_path or ""
        compose = [p.strip() for p in compose_raw.split("\n") if p.strip()]

        if compose and (not github_repository_name):
            raise ValueError("GitHub repository name is required when any workflow path is set.")

        if github_repository_name and ("/" in github_repository_name):
            raise ValueError("GitHub repository name must not contain a slash.")

        if compose:
            for p in compose:
                if not p.startswith(".github/workflows/"):
                    raise ValueError("GitHub workflow paths must start with '.github/workflows/'.")

        return self


class VotePolicyForm(form.Form):
    variant: VOTE = form.value(VOTE)
    project_name: str = form.label("Project name", widget=form.Widget.HIDDEN)
    github_vote_workflow_path: str = form.label(
        "GitHub vote workflow paths",
        "The full paths to the GitHub workflows to use for the release, including the .github/workflows/ prefix.",
        widget=form.Widget.TEXTAREA,
    )
    mailto_addresses: form.Email = form.label(
        "Email",
        f"The mailing list where vote emails are sent. This is usually your dev list. "
        f"ATR will currently only send test announcement emails to {util.USER_TESTS_ADDRESS}.",
    )
    manual_vote: form.Bool = form.label(
        "Manual voting process",
        "If this is set then the vote will be completely manual and following policy is ignored.",
    )
    min_hours: form.Int = form.label(
        "Minimum voting period",
        "The minimum time to run the vote, in hours. Must be 0 or between 72 and 144 inclusive. "
        "If 0, then wait until 3 +1 votes and more +1 than -1.",
        default=72,
    )
    pause_for_rm: form.Bool = form.label(
        "Pause for RM",
        "If enabled, RM can confirm manually if the vote has passed.",
    )
    release_checklist: str = form.label(
        "Release checklist",
        "Markdown text describing how to test release candidates.",
        widget=form.Widget.TEXTAREA,
    )
    start_vote_template: str = form.label(
        "Start vote template",
        "Email template for messages to start a vote on a release.",
        widget=form.Widget.TEXTAREA,
    )

    @pydantic.model_validator(mode="after")
    def validate_vote_fields(self) -> VotePolicyForm:
        vote_raw = self.github_vote_workflow_path or ""
        vote = [p.strip() for p in vote_raw.split("\n") if p.strip()]

        if vote:
            for p in vote:
                if not p.startswith(".github/workflows/"):
                    raise ValueError("GitHub workflow paths must start with '.github/workflows/'.")

        min_hours = self.min_hours
        if min_hours != 0 and (min_hours < 72 or min_hours > 144):
            raise ValueError("Minimum voting period must be 0 or between 72 and 144 hours inclusive.")

        return self


class FinishPolicyForm(form.Form):
    variant: FINISH = form.value(FINISH)
    project_name: str = form.label("Project name", widget=form.Widget.HIDDEN)
    github_finish_workflow_path: str = form.label(
        "GitHub finish workflow paths",
        "The full paths to the GitHub workflows to use for the release, including the .github/workflows/ prefix.",
        widget=form.Widget.TEXTAREA,
    )
    announce_release_template: str = form.label(
        "Announce release template",
        "Email template for messages to announce a finished release.",
        widget=form.Widget.TEXTAREA,
    )
    preserve_download_files: form.Bool = form.label(
        "Preserve download files",
        "If enabled, existing download files will not be overwritten.",
    )

    @pydantic.model_validator(mode="after")
    def validate_finish_fields(self) -> FinishPolicyForm:
        finish_raw = self.github_finish_workflow_path or ""
        finish = [p.strip() for p in finish_raw.split("\n") if p.strip()]

        if finish:
            for p in finish:
                if not p.startswith(".github/workflows/"):
                    raise ValueError("GitHub workflow paths must start with '.github/workflows/'.")

        return self


class AddCategoryForm(form.Form):
    variant: ADD_CATEGORY = form.value(ADD_CATEGORY)
    project_name: str = form.label("Project name", widget=form.Widget.HIDDEN)
    category_to_add: str = form.label("New category name")


class RemoveCategoryForm(form.Form):
    variant: REMOVE_CATEGORY = form.value(REMOVE_CATEGORY)
    project_name: str = form.label("Project name", widget=form.Widget.HIDDEN)
    category_to_remove: str = form.label("Category to remove", widget=form.Widget.HIDDEN)


class AddLanguageForm(form.Form):
    variant: ADD_LANGUAGE = form.value(ADD_LANGUAGE)
    project_name: str = form.label("Project name", widget=form.Widget.HIDDEN)
    language_to_add: str = form.label("New language name")


class RemoveLanguageForm(form.Form):
    variant: REMOVE_LANGUAGE = form.value(REMOVE_LANGUAGE)
    project_name: str = form.label("Project name", widget=form.Widget.HIDDEN)
    language_to_remove: str = form.label("Language to remove", widget=form.Widget.HIDDEN)


class DeleteProjectForm(form.Form):
    variant: DELETE_PROJECT = form.value(DELETE_PROJECT)
    project_name: str = form.label("Project name", widget=form.Widget.HIDDEN)


type ProjectViewForm = Annotated[
    ComposePolicyForm
    | VotePolicyForm
    | FinishPolicyForm
    | AddCategoryForm
    | RemoveCategoryForm
    | AddLanguageForm
    | RemoveLanguageForm
    | DeleteProjectForm,
    form.DISCRIMINATOR,
]


async def add_project(session: web.Committer, committee_name: str) -> web.WerkzeugResponse | str:
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


async def _project_add(form: AddForm, session: web.Committer) -> web.WerkzeugResponse:
    form_values = await _project_add_validate(form)
    if form_values is None:
        return quart.redirect(util.as_url(get.projects.add_project, committee_name=form.committee_name.data))
    committee_name, display_name, label = form_values

    async with storage.write(session) as write:
        wacm = await write.as_project_committee_member(committee_name)
        try:
            await wacm.project.create(committee_name, display_name, label)
        except storage.AccessError as e:
            await quart.flash(f"Error adding project: {e}", "error")
            return quart.redirect(util.as_url(get.projects.add_project, committee_name=committee_name))

    return quart.redirect(util.as_url(get.projects.view, name=label))


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
