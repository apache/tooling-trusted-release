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

import pydantic

import atr.form as form
import atr.util as util

type COMPOSE = Literal["compose"]
type VOTE = Literal["vote"]
type FINISH = Literal["finish"]
type ADD_CATEGORY = Literal["add_category"]
type REMOVE_CATEGORY = Literal["remove_category"]
type ADD_LANGUAGE = Literal["add_language"]
type REMOVE_LANGUAGE = Literal["remove_language"]
type DELETE_PROJECT = Literal["delete_project"]


class AddProjectForm(form.Form):
    committee_name: str = form.label("Committee name", widget=form.Widget.HIDDEN)
    display_name: str = form.label(
        "Display name",
        'For example, "Apache Example" or "Apache Example Components". '
        'You must start with "Apache " and you must use title case.',
    )
    label: str = form.label(
        "Label",
        'For example, "example" or "example-components". '
        "You must start with your committee label, and you must use lower case.",
    )

    @pydantic.model_validator(mode="after")
    def validate_fields(self) -> AddProjectForm:
        committee_name = self.committee_name
        display_name = self.display_name.strip()
        label = self.label.strip()

        # Normalise spaces in the display name
        display_name = re.sub(r"  +", " ", display_name)

        # We must use object.__setattr__ to avoid calling the model validator again
        object.__setattr__(self, "display_name", display_name)

        # Validate display name starts with "Apache"
        display_name_words = display_name.split(" ")
        if display_name_words[0] != "Apache":
            raise ValueError("The first display name word must be 'Apache'.")

        # Validate display name has at least two words
        if not display_name_words[1:]:
            raise ValueError("The display name must have at least two words.")

        # Validate display name uses correct case
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
                raise ValueError("Display name words must be in PascalCase, camelCase, or mod_ case.")

        # Validate display name is alphanumeric with spaces, dots, and plus signs
        if not display_name.replace(" ", "").replace(".", "").replace("+", "").isalnum():
            raise ValueError("Display name must be alphanumeric and may include spaces or dots or plus signs.")

        # Validate label starts with committee name
        if not (label.startswith(committee_name + "-") or (label == committee_name)):
            raise ValueError(f"Label must be '{committee_name}' or start with '{committee_name}-'.")

        # Validate label is lowercase
        if not label.islower():
            raise ValueError("Label must be all lower case.")

        # Validate label is alphanumeric with hyphens
        if not label.replace("-", "").isalnum():
            raise ValueError("Label must be alphanumeric and may include hyphens.")

        return self


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
