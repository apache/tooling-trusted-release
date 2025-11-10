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

import asfquart.base as base

import atr.blueprints.get as get
import atr.db as db
import atr.db.interaction as interaction
import atr.form as form
import atr.get.root as root
import atr.htm as htm
import atr.models.sql as sql
import atr.shared as shared
import atr.template as template
import atr.util as util
import atr.web as web


@get.committer("/start/<project_name>")
async def selected(session: web.Committer, project_name: str) -> str:
    await session.check_access(project_name)

    async with db.session() as data:
        project = await data.project(name=project_name, status=sql.ProjectStatus.ACTIVE).demand(
            base.ASFQuartException(f"Project {project_name} not found", errorcode=404)
        )

    releases = await interaction.all_releases(project)
    content = await _render_page(project, releases)
    return await template.blank(
        title=f"Start a new release for {project.display_name}",
        content=content,
    )


async def _render_page(project: sql.Project, releases: list[sql.Release]) -> htm.Element:
    page = htm.Block()

    page.h1[f"Start a new release for {project.display_name}"]
    page.p[
        "Starting a new release creates a ",
        htm.strong["release candidate draft"],
        ". You can then add files to this draft before promoting it for voting.",
    ]
    form.render_block(
        page,
        model_cls=shared.start.StartReleaseForm,
        form_classes=".atr-canary.py-4.px-5.border.rounded",
        submit_classes="btn-primary btn-lg",
        submit_label="Start new release",
        cancel_url=util.as_url(root.index),
        defaults={"project_name": project.name},
    )
    if releases:
        page.h2(".mt-5")["Existing releases"]
        with page.block(htm.div, classes=".row") as row:
            with row.block(htm.div, classes=".col-12") as col:
                with col.block(htm.ul, classes=".list-unstyled.row.g-3") as ul:
                    _existing_releases(ul, releases)

    return page.collect()


def _existing_releases(ul: htm.Block, releases: list[sql.Release], max_revisions: int = 18) -> None:
    for i, release in enumerate(releases):
        if i >= max_revisions:
            break

        phase_symbol = _get_phase_symbol(release.phase)
        ul.li(".col-6.col-sm-4.col-md-3.col-lg-2")[
            htm.div(".text-nowrap")[
                htm.span(class_="atr-phase-symbol fs-6")[phase_symbol],
                " ",
                release.version,
            ]
        ]

    if len(releases) > max_revisions:
        ul.li(".col-6.col-sm-4.col-md-3.col-lg-2")[
            htm.div(".text-center")[
                htm.strong["..."],
                " ",
                htm.span(".text-muted.ms-1")[f"{len(releases) - max_revisions} more"],
            ]
        ]


def _get_phase_symbol(phase: sql.ReleasePhase) -> str:
    match phase:
        case sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
            return "①"
        case sql.ReleasePhase.RELEASE_CANDIDATE:
            return "②"
        case sql.ReleasePhase.RELEASE_PREVIEW:
            return "③"
        case sql.ReleasePhase.RELEASE:
            return "Ⓡ"
