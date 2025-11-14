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

import atr.blueprints.get as get
import atr.db as db
import atr.db.interaction as interaction
import atr.form as form
import atr.get.compose as compose
import atr.get.vote as vote
import atr.htm as htm
import atr.models.sql as sql
import atr.post as post
import atr.shared as shared
import atr.template as template
import atr.util as util
import atr.web as web


@get.committer("/manual/resolve/<project_name>/<version_name>")
async def resolve_selected(session: web.Committer, project_name: str, version_name: str) -> str:
    """Get the manual vote resolution page."""
    await session.check_access(project_name)

    release = await session.release(
        project_name,
        version_name,
        phase=sql.ReleasePhase.RELEASE_CANDIDATE,
        with_release_policy=True,
        with_project_release_policy=True,
    )
    if not release.vote_manual:
        raise RuntimeError("This page is for manual votes only")

    content = _render_resolve_page(release)

    return await template.blank(
        title="Resolve vote",
        description="Resolve vote for a release.",
        content=content,
    )


def _render_resolve_page(release: sql.Release) -> htm.Element:
    page = htm.Block()

    back_url = util.as_url(vote.selected, project_name=release.project.name, version_name=release.version)
    page.p[htm.a(".atr-back-link", href=back_url)[f"← Back to Vote for {release.short_display_name}"]]

    page.h1[f"Resolve vote for {release.short_display_name}"]
    page.p["This is a manual vote resolution."]

    form.render_block(
        page,
        model_cls=shared.manual.ResolveVoteForm,
        form_classes=".atr-canary.py-4.px-5.mb-4.border.rounded",
        submit_label="Resolve vote",
    )

    return page.collect()


@get.committer("/manual/start/<project_name>/<version_name>/<revision>")
async def start_selected_revision(
    session: web.Committer, project_name: str, version_name: str, revision: str
) -> web.WerkzeugResponse | str:
    await session.check_access(project_name)

    async with db.session() as data:
        match await interaction.release_ready_for_vote(
            session, project_name, version_name, revision, data, manual_vote=True
        ):
            case str() as error:
                return await session.redirect(
                    compose.selected,
                    error=error,
                    project_name=project_name,
                    version_name=version_name,
                    revision=revision,
                )
            case (release, _committee):
                pass

        content = await _render_page(release=release, revision=revision)

        return await template.blank(
            title=f"Start manual vote on {release.project.short_display_name} {release.version}", content=content
        )


async def _render_page(release, revision: str) -> htm.Element:
    page = htm.Block()

    back_link_url = util.as_url(
        compose.selected,
        project_name=release.project.name,
        version_name=release.version,
    )
    shared.distribution.html_nav(
        page,
        back_link_url,
        f"Compose {release.short_display_name}",
        "COMPOSE",
    )

    page.h1(".mb-4")[
        "Start manual vote on ",
        htm.strong[release.project.short_display_name],
        " ",
        htm.em[release.version],
    ]

    page.div(".px-3.py-4.mb-4.bg-light.border.rounded")[
        htm.p(".mb-0")[
            "This release has the manual vote process enabled. "
            "Press the button below to promote this release to candidate status."
        ]
    ]

    page.p[
        "Once the vote is started, you must manually send the vote email to the appropriate mailing list, "
        "wait for the vote to complete, and then manually advance the release to the next phase. "
        "The ATR will then require you to submit the vote and vote result thread URLs to proceed."
    ]

    cancel_url = util.as_url(compose.selected, project_name=release.project.name, version_name=release.version)
    manual_form = form.render(
        model_cls=form.Empty,
        submit_label="Start manual vote",
        cancel_url=cancel_url,
        action=util.as_url(
            post.manual.start_selected_revision,
            project_name=release.project.name,
            version_name=release.version,
            revision=revision,
        ),
    )

    page.append(manual_form)

    return page.collect()
