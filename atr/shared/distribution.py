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

import json
from typing import Literal

import pydantic

import atr.db as db
import atr.form as form
import atr.get as get
import atr.htm as htm
import atr.models.distribution as distribution
import atr.models.sql as sql
import atr.storage as storage
import atr.template as template
import atr.util as util

type Phase = Literal["COMPOSE", "VOTE", "FINISH"]


class DeleteForm(form.Form):
    release_name: str = form.label("Release name", widget=form.Widget.HIDDEN)
    platform: str = form.label("Platform", widget=form.Widget.HIDDEN)
    owner_namespace: str = form.label("Owner namespace", widget=form.Widget.HIDDEN)
    package: str = form.label("Package", widget=form.Widget.HIDDEN)
    version: str = form.label("Version", widget=form.Widget.HIDDEN)


class DistributeForm(form.Form):
    platform: sql.DistributionPlatform = form.label("Platform", widget=form.Widget.SELECT)
    owner_namespace: str | None = form.label(
        description="Owner or Namespace",
        documentation=(
            "Who owns or names the package (Maven groupId, npm @scope, Docker namespace, "
            "GitHub owner, ArtifactHub repo). Leave blank if not used."
        ),
        widget=form.Widget.TEXT,
    )
    package: str = form.label("Package", widget=form.Widget.TEXT)
    version: str = form.label("Version", widget=form.Widget.TEXT)
    details: bool = form.label(
        description="Include details",
        documentation="Include the details of the distribution in the response",
        widget=form.Widget.CHECKBOX,
    )

    @pydantic.model_validator(mode="after")
    def validate_owner_namespace(self):
        if not self.platform:
            raise ValueError("Platform is required")

        default_owner_namespace = self.platform.value.default_owner_namespace
        requires_owner_namespace = self.platform.value.requires_owner_namespace

        # TODO: We should disable the owner_namespace field if it's not required
        # But that would be a lot of complexity
        # And this validation, which we need to keep, is complex enough
        if default_owner_namespace and not self.owner_namespace:
            self.owner_namespace = default_owner_namespace

        if requires_owner_namespace and not self.owner_namespace:
            raise ValueError(f'Platform "{self.platform.name}" requires an owner or namespace.')

        if not requires_owner_namespace and not default_owner_namespace and self.owner_namespace:
            raise ValueError(f'Platform "{self.platform.name}" does not require an owner or namespace.')

        return self


# TODO: Move this to an appropriate module
def html_nav(container: htm.Block, back_url: str, back_anchor: str, phase: Phase) -> None:
    classes = ".d-flex.justify-content-between.align-items-center"
    block = htm.Block(htm.p, classes=classes)
    block.a(".atr-back-link", href=back_url)[f"← Back to {back_anchor}"]
    span = htm.Block(htm.span)

    def _phase(actual: Phase, expected: Phase) -> None:
        # nonlocal span
        match expected:
            case "COMPOSE":
                symbol = "①"
            case "VOTE":
                symbol = "②"
            case "FINISH":
                symbol = "③"
        if actual == expected:
            span.strong(f".atr-phase-{actual}.atr-phase-symbol")[symbol]
            span.span(f".atr-phase-{actual}.atr-phase-label")[actual]
        else:
            span.span(".atr-phase-symbol-other")[symbol]

    _phase(phase, "COMPOSE")
    span.span(".atr-phase-arrow")["→"]
    _phase(phase, "VOTE")
    span.span(".atr-phase-arrow")["→"]
    _phase(phase, "FINISH")

    block.append(span.collect(separator=" "))
    container.append(block)


def html_nav_phase(block: htm.Block, project: str, version: str, staging: bool) -> None:
    label: Phase
    route, label = (get.compose.selected, "COMPOSE")
    if not staging:
        route, label = (get.finish.selected, "FINISH")
    html_nav(
        block,
        util.as_url(
            route,
            project_name=project,
            version_name=version,
        ),
        back_anchor=f"{label.title()} {project} {version}",
        phase=label,
    )


def html_submitted_values_table(block: htm.Block, dd: distribution.Data) -> None:
    tbody = htm.tbody[
        html_tr("Platform", dd.platform.name),
        html_tr("Owner or Namespace", dd.owner_namespace or "-"),
        html_tr("Package", dd.package),
        html_tr("Version", dd.version),
    ]
    block.table(".table.table-striped.table-bordered")[tbody]


def html_tr(label: str, value: str) -> htm.Element:
    return htm.tr[htm.th[label], htm.td[value]]


def html_tr_a(label: str, value: str | None) -> htm.Element:
    return htm.tr[htm.th[label], htm.td[htm.a(href=value)[value] if value else "-"]]


async def record_form_process_page_new(
    form_data: DistributeForm, project: str, version: str, /, staging: bool = False
) -> str:
    dd = distribution.Data.model_validate(form_data.model_dump())
    release, committee = await release_validated_and_committee(
        project,
        version,
        staging=staging,
    )

    # In case of error, show an alert
    async def _alert(message: str) -> str:
        div = htm.Block(htm.div(".alert.alert-danger"))
        div.p[message]
        collected = div.collect()
        return await record_form_page_new(form_data, project, version, extra_content=collected, staging=staging)

    async with storage.write_as_committee_member(committee_name=committee.name) as w:
        try:
            dist, added, metadata = await w.distributions.record_from_data(
                release=release,
                staging=staging,
                dd=dd,
            )
        except storage.AccessError as e:
            return await _alert(str(e))

    block = htm.Block()

    # Distribution submitted
    block.h1["Distribution recorded"]

    ## Record
    block.h2["Record"]
    if added:
        block.p["The distribution was recorded successfully."]
    else:
        block.p["The distribution was already recorded."]
    block.table(".table.table-striped.table-bordered")[
        htm.tbody[
            html_tr("Release name", dist.release_name),
            html_tr("Platform", dist.platform.name),
            html_tr("Owner or Namespace", dist.owner_namespace or "-"),
            html_tr("Package", dist.package),
            html_tr("Version", dist.version),
            html_tr("Staging", "Yes" if dist.staging else "No"),
            html_tr("Upload date", str(dist.upload_date)),
            html_tr_a("API URL", dist.api_url),
            html_tr_a("Web URL", dist.web_url),
        ]
    ]
    block.p[
        htm.a(href=util.as_url(get.distribution.list_get, project=project, version=version))[
            "Back to distribution list"
        ],
    ]

    if dd.details:
        ## Details
        block.h2["Details"]

        ### Submitted values
        block.h3["Submitted values"]
        html_submitted_values_table(block, dd)

        ### As JSON
        block.h3["As JSON"]
        block.pre(".mb-3")[dd.model_dump_json(indent=2)]

        ### API URL
        block.h3["API URL"]
        block.pre(".mb-3")[metadata.api_url]

        ### API response
        block.h3["API response"]
        block.details[
            htm.summary["Show full API response"],
            htm.pre(".atr-pre-wrap.mb-3")[json.dumps(metadata.result, indent=2)],
        ]

    return await template.blank("Distribution submitted", content=block.collect())


async def record_form_page_new(
    form_data: DistributeForm,
    project: str,
    version: str,
    *,
    extra_content: htm.Element | None = None,
    staging: bool = False,
) -> str:
    await release_validated(project, version, staging=staging)

    # Render the explanation and form
    block = htm.Block()
    html_nav_phase(block, project, version, staging)

    # Record a manual distribution
    title_and_heading = f"Record a {'staging' if staging else 'manual'} distribution"
    block.h1[title_and_heading]
    if extra_content:
        block.append(extra_content)
    block.p[
        "Record a distribution of ",
        htm.strong[f"{project}-{version}"],
        " using the form below.",
    ]
    block.p[
        "You can also ",
        htm.a(href=util.as_url(get.distribution.list_get, project=project, version=version))[
            "view the distribution list"
        ],
        ".",
    ]

    # Use form.render instead of forms.render_columns
    action_url = util.as_url(
        get.distribution.stage if staging else get.distribution.record,
        project=project,
        version=version,
    )
    form_html = form.render(
        model_cls=DistributeForm,
        submit_label="Record distribution",
        action=action_url,
        defaults=form_data.model_dump() if form_data else None,
    )
    block.append(form_html)

    # Render the page
    return await template.blank(title_and_heading, content=block.collect())


async def release_validated_and_committee(
    project: str,
    version: str,
    *,
    staging: bool | None = None,
) -> tuple[sql.Release, sql.Committee]:
    release = await release_validated(project, version, committee=True, staging=staging)
    committee = release.committee
    if committee is None:
        raise RuntimeError(f"Release {project} {version} has no committee")
    return release, committee


async def release_validated(
    project: str,
    version: str,
    committee: bool = False,
    staging: bool | None = None,
) -> sql.Release:
    match staging:
        case True:
            phase = {sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT}
        case False:
            phase = {sql.ReleasePhase.RELEASE_PREVIEW}
        case None:
            phase = {sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT, sql.ReleasePhase.RELEASE_PREVIEW}
    async with db.session() as data:
        release = await data.release(
            project_name=project,
            version=version,
            _committee=committee,
        ).demand(RuntimeError(f"Release {project} {version} not found"))
        if release.phase not in phase:
            raise RuntimeError(f"Release {project} {version} is not in {phase}")
        # if release.project.status != sql.ProjectStatus.ACTIVE:
        #     raise RuntimeError(f"Project {project} is not active")
    return release
