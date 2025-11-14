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

import asfquart.base as base
import htpy
import markupsafe

import atr.blueprints.get as get
import atr.config as config
import atr.db as db
import atr.db.interaction as interaction
import atr.form as form
import atr.forms as forms
import atr.get.committees as committees
import atr.get.draft as draft
import atr.get.preview as preview
import atr.get.release as release
import atr.get.start as start
import atr.htm as htm
import atr.models.sql as sql
import atr.post as post
import atr.registry as registry
import atr.shared as shared
import atr.template as template
import atr.user as user
import atr.util as util
import atr.web as web
from atr.get import candidate


@get.committer("/project/add/<committee_name>")
async def add_project(session: web.Committer, committee_name: str) -> web.WerkzeugResponse | str:
    await session.check_access_committee(committee_name)

    async with db.session() as data:
        committee = await data.committee(name=committee_name).demand(
            base.ASFQuartException(f"Committee {committee_name} not found", errorcode=404)
        )

    page = htm.Block()
    page.p[htm.a(".atr-back-link", href=util.as_url(committees.view, name=committee_name))["← Back to committee"]]
    page.h1["Add project"]
    page.p[f"Add a new project to the {committee.display_name} committee."]

    committee_display_name = committee.full_name or committee_name.title()

    form.render_block(
        page,
        model_cls=shared.projects.AddProjectForm,
        action=util.as_url(post.projects.add_project, committee_name=committee_name),
        submit_label="Add project",
        cancel_url=util.as_url(committees.view, name=committee_name),
        defaults={
            "committee_name": committee_name,
        },
    )

    script_text = markupsafe.Markup(f"""
document.addEventListener("DOMContentLoaded", function() {{
    const committeeInput = document.querySelector('input[name="committee_name"]');
    if (committeeInput) {{
        const committeeName = committeeInput.value;
        const committeeDisplayName = "{committee_display_name}";
        const formTexts = document.querySelectorAll('.form-text, .text-muted');
        formTexts.forEach(function(element) {{
            element.textContent = element.textContent.replace(/Example/g, committeeDisplayName);
            element.textContent = element.textContent.replace(/example/g, committeeName.toLowerCase());
        }});
    }}
}});
""")
    page.append(htm.script[script_text])

    return await template.blank(
        title="Add project",
        description=f"Add a new project to the {committee.display_name} committee.",
        content=page.collect(),
    )


@get.public("/projects")
async def projects(session: web.Committer | None) -> str:
    """Main project directory page."""
    async with db.session() as data:
        projects = await data.project(_committee=True).order_by(sql.Project.full_name).all()
        return await template.render("projects.html", projects=projects, empty_form=await forms.Empty.create_form())


@get.committer("/project/select")
async def select(session: web.Committer) -> str:
    """Select a project to work on."""
    user_projects = []
    if session.uid:
        async with db.session() as data:
            # TODO: Move this filtering logic somewhere else
            # The ALLOW_TESTS line allows test projects to be shown
            conf = config.get()
            all_projects = await data.project(status=sql.ProjectStatus.ACTIVE, _committee=True).all()
            user_projects = [
                p
                for p in all_projects
                if p.committee
                and (
                    (conf.ALLOW_TESTS and (p.committee.name == "test"))
                    or (session.uid in p.committee.committee_members)
                    or (session.uid in p.committee.committers)
                    or (session.uid in p.committee.release_managers)
                )
            ]
            user_projects.sort(key=lambda p: p.display_name)

    return await template.render("project-select.html", user_projects=user_projects)


@get.committer("/projects/<name>")
async def view(session: web.Committer, name: str) -> web.WerkzeugResponse | str:
    async with db.session() as data:
        project = await data.project(
            name=name, _committee=True, _committee_public_signing_keys=True, _release_policy=True
        ).demand(base.ASFQuartException(f"Project {name} not found", errorcode=404))

    is_committee_member = project.committee and (user.is_committee_member(project.committee, session.uid))
    is_privileged = user.is_admin(session.uid)
    can_edit = is_committee_member or is_privileged

    candidate_drafts = await interaction.candidate_drafts(project)
    candidates = await interaction.candidates(project)
    previews = await interaction.previews(project)
    full_releases = await interaction.full_releases(project)

    page = htm.Block()

    page_styles = """
        .page-remove-tag {
            font-size: 0.65em;
            padding: 0.2em 0.3em;
            cursor: pointer;
        }
    """
    page.style[page_styles]

    title_row = htm.div(".row")[
        htm.div(".col-md")[htm.h1[project.display_name]],
        htm.div(".col-sm-auto")[htm.span(".badge.text-bg-secondary")[project.status.value.lower()]]
        if project.status.value.lower() != "active"
        else "",
    ]
    page.append(title_row)

    page.p(".mb-4")[
        htm.a(".btn.btn-sm.btn-outline-primary", href=util.as_url(start.selected, project_name=project.name))[
            "Start a new release"
        ]
    ]

    page.append(_render_project_label_card(project))
    page.append(_render_pmc_card(project))
    page.append(_render_description_card(project))

    if project.status == sql.ProjectStatus.ACTIVE:
        if can_edit:
            page.append(_render_compose_form(project))
            page.append(_render_vote_form(project))
            page.append(_render_finish_form(project))
        else:
            page.append(_render_policy_readonly(project))

    if can_edit:
        page.append(_render_categories_section(project))
        page.append(_render_languages_section(project))

    if is_committee_member or is_privileged:
        page.append(await _render_releases_sections(project, candidate_drafts, candidates, previews, full_releases))

        if project.created_by == session.uid:
            page.append(_render_delete_section(project))

        if is_committee_member or is_privileged:
            if project.committee:
                page.p[
                    htm.a(
                        ".btn.btn-sm.btn-outline-primary",
                        href=util.as_url(add_project, committee_name=project.committee.name),
                    )["Create a sibling project"]
                ]

    content = page.collect()

    return await template.blank(
        title=f"{project.display_name}",
        description=f"Information regarding {project.display_name}.",
        content=content,
    )


def _render_categories_section(project: sql.Project) -> htm.Element:
    card = htm.Block(htm.div, classes=".card.mb-4")
    card.div(".card-header.bg-light")[htm.h3(".mb-2")["Categories"]]

    current_categories = project.category.split(", ") if project.category else []
    category_badges = []
    for cat in current_categories:
        remove_button = (
            # Manual form as badges are not handled by the form system
            htm.form(".d-inline.m-0", method="post", action=util.as_url(post.projects.view, name=project.name))[
                form.csrf_input(),
                htpy.input(type="hidden", name="project_name", value=project.name),
                htpy.input(type="hidden", name="variant", value="remove_category"),
                htpy.input(type="hidden", name="category_to_remove", value=cat),
                htpy.button(
                    ".btn-close.btn-close-white.ms-1.page-remove-tag", type="submit", aria_label=f"Remove {cat}"
                ),
            ]
            if cat not in registry.FORBIDDEN_PROJECT_CATEGORIES
            else ""
        )
        badge = htm.div(".badge.bg-primary.d-inline-flex.align-items-center.px-2.py-1")[
            htm.span[cat],
            remove_button,
        ]
        category_badges.append(badge)

    add_form = htm.form(".mb-3", method="post", action=util.as_url(post.projects.view, name=project.name))[
        form.csrf_input(),
        htpy.input(type="hidden", name="project_name", value=project.name),
        htpy.input(type="hidden", name="variant", value="add_category"),
        htm.div(".d-flex.align-items-center")[
            htpy.input(
                ".form-control.form-control-sm.me-2", type="text", name="category_to_add", placeholder="New category"
            ),
            htpy.button(".btn.btn-sm.btn-success.text-nowrap.pe-3", type="submit")[htpy.i(".bi.bi-plus"), " Add"],
        ],
    ]

    with card.block(htm.div, classes=".card-body") as card_body:
        card_body.append(add_form)
        if category_badges:
            card_body.append(htm.div(".d-flex.flex-wrap.gap-2.align-items-center.mt-3")[*category_badges])
    return card.collect()


def _render_compose_form(project: sql.Project) -> htm.Element:
    card = htm.Block(htm.div, classes=".card.mb-4")
    card.div(".card-header.bg-light.d-flex.justify-content-between.align-items-center")[
        htm.h3(".mb-0")["Release policy - Compose options"]
    ]

    with card.block(htm.div, classes=".card-body") as card_body:
        form.render_block(
            card_body,
            model_cls=shared.projects.ComposePolicyForm,
            action=util.as_url(post.projects.view, name=project.name),
            submit_label="Save",
            defaults={
                "project_name": project.name,
                "source_artifact_paths": "\n".join(project.policy_source_artifact_paths),
                "binary_artifact_paths": "\n".join(project.policy_binary_artifact_paths),
                "github_repository_name": project.policy_github_repository_name or "",
                "github_compose_workflow_path": "\n".join(project.policy_github_compose_workflow_path),
                "strict_checking": project.policy_strict_checking,
            },
            form_classes=".atr-canary.py-4.px-5",
            border=True,
            # wider_widgets=True,
            textarea_rows=5,
        )
    return card.collect()


def _render_delete_section(project: sql.Project) -> htm.Element:
    section = htm.Block(htm.div)
    section.h2["Actions"]

    delete_form = htm.form(
        ".d-inline-block.m-0",
        method="post",
        action=util.as_url(post.projects.view, name=project.name),
        onsubmit=(
            f"return confirm('Are you sure you want to delete the project "
            f"\\'{project.display_name}\\'? This cannot be undone.');"
        ),
    )[
        form.csrf_input(),
        htpy.input(type="hidden", name="project_name", value=project.name),
        htpy.input(type="hidden", name="variant", value="delete_project"),
        htpy.button(".btn.btn-sm.btn-outline-danger", type="submit", title=f"Delete {project.display_name}")[
            htpy.i(".bi.bi-trash"), " Delete project"
        ],
    ]

    section.div(".my-3")[delete_form]
    return section.collect()


def _render_description_card(project: sql.Project) -> htm.Element:
    card = htm.Block(htm.div, classes=".card.mb-4")
    card.div(".card-header.bg-light")[htm.h3(".mb-2")["Description"]]
    card.div(".card-body")[htm.div(".d-flex.flex-wrap.gap-3.small.mb-1")[htm.span(".fs-6")[project.description]]]
    return card.collect()


def _render_finish_form(project: sql.Project) -> htm.Element:
    card = htm.Block(htm.div, classes=".card.mb-4")
    card.div(".card-header.bg-light.d-flex.justify-content-between.align-items-center")[
        htm.h3(".mb-0")["Release policy - Finish options"]
    ]

    with card.block(htm.div, classes=".card-body") as card_body:
        form.render_block(
            card_body,
            model_cls=shared.projects.FinishPolicyForm,
            action=util.as_url(post.projects.view, name=project.name),
            submit_label="Save",
            defaults={
                "project_name": project.name,
                "github_finish_workflow_path": "\n".join(project.policy_github_finish_workflow_path),
                "announce_release_template": project.policy_announce_release_template or "",
                "preserve_download_files": project.policy_preserve_download_files,
            },
            form_classes=".atr-canary.py-4.px-5",
            border=True,
            # wider_widgets=True,
            textarea_rows=10,
        )
    return card.collect()


def _render_languages_section(project: sql.Project) -> htm.Element:
    card = htm.Block(htm.div, classes=".card.mb-4")
    card.div(".card-header.bg-light")[htm.h3(".mb-2")["Programming languages"]]

    current_languages = project.programming_languages.split(", ") if project.programming_languages else []
    language_badges = []
    for lang in current_languages:
        # Manual form as badges are not handled by the form system
        remove_button = htm.form(
            ".d-inline.m-0", method="post", action=util.as_url(post.projects.view, name=project.name)
        )[
            form.csrf_input(),
            htpy.input(type="hidden", name="project_name", value=project.name),
            htpy.input(type="hidden", name="variant", value="remove_language"),
            htpy.input(type="hidden", name="language_to_remove", value=lang),
            htpy.button(".btn-close.btn-close-white.ms-1.page-remove-tag", type="submit", aria_label=f"Remove {lang}"),
        ]
        badge = htm.div(".badge.bg-success.d-inline-flex.align-items-center.px-2.py-1")[
            htm.span[lang],
            remove_button,
        ]
        language_badges.append(badge)

    add_form = htm.form(".mb-3", method="post", action=util.as_url(post.projects.view, name=project.name))[
        form.csrf_input(),
        htpy.input(type="hidden", name="project_name", value=project.name),
        htpy.input(type="hidden", name="variant", value="add_language"),
        htm.div(".d-flex.align-items-center")[
            htpy.input(
                ".form-control.form-control-sm.me-2", type="text", name="language_to_add", placeholder="New language"
            ),
            htpy.button(".btn.btn-sm.btn-success.text-nowrap.pe-3", type="submit")[htpy.i(".bi.bi-plus"), " Add"],
        ],
    ]

    with card.block(htm.div, classes=".card-body") as card_body:
        card_body.append(add_form)
        if language_badges:
            card_body.append(htm.div(".d-flex.flex-wrap.gap-2.align-items-center.mt-3")[*language_badges])
    return card.collect()


def _render_pmc_card(project: sql.Project) -> htm.Element:
    card = htm.Block(htm.div, classes=".card.mb-4")
    card.div(".card-header.bg-light")[htm.h3(".mb-2")["PMC"]]
    if project.committee:
        committee_link = htm.a(href=util.as_url(committees.view, name=project.committee.name))[
            project.committee.display_name
        ]
        card.div(".card-body")[htm.div(".d-flex.flex-wrap.gap-3.small.mb-1")[committee_link]]
    else:
        card.div(".card-body")[htm.div(".d-flex.flex-wrap.gap-3.small.mb-1")["No committee"]]
    return card.collect()


def _render_policy_readonly(project: sql.Project) -> htm.Element:
    card = htm.Block(htm.div, classes=".card.mb-4")
    card.div(".card-header.bg-light")[htm.h3(".mb-2")["Release policy"]]

    email_content = (
        htm.a(href=f"mailto:{project.policy_mailto_addresses[0]}")[project.policy_mailto_addresses[0]]
        if project.policy_mailto_addresses
        else "Not set"
    )

    tbody = htm.tbody[
        htm.tr[
            htm.th(".border-0.w-25")["Email"],
            htm.td(".text-break.border-0")[email_content],
        ],
        htm.tr[
            htm.th(".border-0")["Manual vote process"],
            htm.td(".text-break.border-0")[str(project.policy_manual_vote)],
        ],
        htm.tr[
            htm.th(".border-0")["Minimum voting period"],
            htm.td(".text-break.border-0")[f"{project.policy_min_hours}h"],
        ],
    ]

    card.div(".card-body")[htm.div(".card.h-100.border")[htm.div(".card-body")[htm.table(".table.mb-0")[tbody]]]]
    return card.collect()


def _render_project_label_card(project: sql.Project) -> htm.Element:
    card = htm.Block(htm.div, classes=".card.mb-4")
    card.div(".card-header.bg-light")[htm.h3(".mb-2")["Project label"]]
    card.div(".card-body")[htm.code(".fs-6")[project.name]]
    return card.collect()


async def _render_releases_sections(
    project: sql.Project,
    candidate_drafts: list[sql.Release],
    candidates: list[sql.Release],
    previews: list[sql.Release],
    full_releases: list[sql.Release],
) -> htm.Element:
    sections = htm.Block(htm.div)

    if candidate_drafts:
        sections.h2["Draft candidate releases"]
        draft_buttons = []
        for drf in candidate_drafts:
            file_count = await util.number_of_release_files(drf)
            draft_buttons.append(
                htm.a(
                    ".btn.btn-sm.btn-outline-secondary.py-2.px-3",
                    href=util.as_url(draft.view, project_name=project.name, version_name=drf.version),
                    title=f"View draft {project.name} {drf.version}",
                )[
                    f"{project.name} {drf.version} ",
                    htm.span(".badge.bg-secondary.ms-2")[f"{file_count} {'file' if (file_count == 1) else 'files'}"],
                ]
            )
        sections.div(".d-flex.flex-wrap.gap-2.mb-4")[*draft_buttons]

    if candidates:
        sections.h2["Candidate releases"]
        candidate_buttons = []
        for cnd in candidates:
            file_count = await util.number_of_release_files(cnd)
            candidate_buttons.append(
                htm.a(
                    ".btn.btn-sm.btn-outline-info.py-2.px-3",
                    href=util.as_url(candidate.view, project_name=project.name, version_name=cnd.version),
                    title=f"View candidate {project.name} {cnd.version}",
                )[
                    f"{project.name} {cnd.version} ",
                    htm.span(".badge.bg-info.ms-2")[f"{file_count} {'file' if (file_count == 1) else 'files'}"],
                ]
            )
        sections.div(".d-flex.flex-wrap.gap-2.mb-4")[*candidate_buttons]

    if previews:
        sections.h2["Preview releases"]
        preview_buttons = []
        for prv in previews:
            file_count = await util.number_of_release_files(prv)
            preview_buttons.append(
                htm.a(
                    ".btn.btn-sm.btn-outline-warning.py-2.px-3",
                    href=util.as_url(preview.view, project_name=project.name, version_name=prv.version),
                    title=f"View preview {project.name} {prv.version}",
                )[
                    f"{project.name} {prv.version} ",
                    htm.span(".badge.bg-warning.ms-2")[f"{file_count} {'file' if (file_count == 1) else 'files'}"],
                ]
            )
        sections.div(".d-flex.flex-wrap.gap-2.mb-4")[*preview_buttons]

    if full_releases:
        sections.h2["Full releases"]
        release_buttons = []
        for rel in full_releases:
            file_count = await util.number_of_release_files(rel)
            release_buttons.append(
                htm.a(
                    ".btn.btn-sm.btn-outline-success.py-2.px-3",
                    href=util.as_url(release.view, project_name=project.name, version_name=rel.version),
                    title=f"View release {project.name} {rel.version}",
                )[
                    f"{project.name} {rel.version} ",
                    htm.span(".badge.bg-success.ms-2")[f"{file_count} {'file' if (file_count == 1) else 'files'}"],
                ]
            )
        sections.div(".d-flex.flex-wrap.gap-2.mb-4")[*release_buttons]

    return sections.collect()


def _render_vote_form(project: sql.Project) -> htm.Element:
    card = htm.Block(htm.div, classes=".card.mb-4")
    card.div(".card-header.bg-light.d-flex.justify-content-between.align-items-center")[
        htm.h3(".mb-0")["Release policy - Vote options"]
    ]

    defaults_dict = {
        "project_name": project.name,
        "github_vote_workflow_path": "\n".join(project.policy_github_vote_workflow_path),
        "mailto_addresses": project.policy_mailto_addresses[0]
        if project.policy_mailto_addresses
        else f"dev@{project.name}.apache.org",
        "manual_vote": project.policy_manual_vote,
        "min_hours": project.policy_min_hours,
        "pause_for_rm": project.policy_pause_for_rm,
        "release_checklist": project.policy_release_checklist or "",
        "start_vote_template": project.policy_start_vote_template or "",
    }

    skip_fields = ["manual_vote"] if (project.committee and project.committee.is_podling) else []

    with card.block(htm.div, classes=".card-body") as card_body:
        form.render_block(
            card_body,
            model_cls=shared.projects.VotePolicyForm,
            action=util.as_url(post.projects.view, name=project.name),
            submit_label="Save",
            defaults=defaults_dict,
            form_classes=".atr-canary.py-4.px-5",
            border=True,
            # wider_widgets=True,
            textarea_rows=10,
            skip=skip_fields,
        )
    return card.collect()
