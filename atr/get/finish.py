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


import dataclasses
import json
import pathlib
from typing import Any

import aiofiles.os
import asfquart.base as base
import htpy
import markupsafe
import quart
import quart_wtf.utils as utils

import atr.analysis as analysis
import atr.blueprints.get as get
import atr.db as db
import atr.form as form
import atr.get.announce as announce
import atr.get.distribution as distribution
import atr.get.download as download
import atr.get.preview as preview
import atr.get.revisions as revisions
import atr.get.root as root
import atr.htm as htm
import atr.mapping as mapping
import atr.models.sql as sql
import atr.shared as shared
import atr.template as template
import atr.util as util
import atr.web as web


@dataclasses.dataclass
class RCTagAnalysisResult:
    affected_paths_preview: list[tuple[str, str]]
    affected_count: int
    total_paths: int


@get.committer("/finish/<project_name>/<version_name>")
async def selected(
    session: web.Committer, project_name: str, version_name: str
) -> tuple[web.QuartResponse, int] | web.WerkzeugResponse | str:
    """Finish a release preview."""
    try:
        (
            release,
            source_files_rel,
            target_dirs,
            deletable_dirs,
            rc_analysis,
        ) = await _get_page_data(project_name, version_name)
    except ValueError:
        async with db.session() as data:
            release_fallback = await data.release(
                project_name=project_name,
                version=version_name,
                _committee=True,
            ).get()
            if release_fallback:
                return await mapping.release_as_redirect(session, release_fallback)

        await quart.flash("Preview revision directory not found.", "error")
        return await session.redirect(root.index)
    except FileNotFoundError:
        await quart.flash("Preview revision directory not found.", "error")
        return await session.redirect(root.index)

    return await _render_page(
        release=release,
        source_files_rel=source_files_rel,
        target_dirs=target_dirs,
        deletable_dirs=deletable_dirs,
        rc_analysis=rc_analysis,
    )


async def _analyse_rc_tags(latest_revision_dir: pathlib.Path) -> RCTagAnalysisResult:
    r = RCTagAnalysisResult(
        affected_paths_preview=[],
        affected_count=0,
        total_paths=0,
    )

    if not latest_revision_dir.exists():
        return r

    async for p_rel in util.paths_recursive_all(latest_revision_dir):
        r.total_paths += 1
        original_path_str = str(p_rel)
        stripped_path_str = str(analysis.candidate_removed(p_rel))
        if original_path_str == stripped_path_str:
            continue
        r.affected_count += 1
        if len(r.affected_paths_preview) >= 5:
            # Can't break here, because we need to update the counts
            continue
        r.affected_paths_preview.append((original_path_str, stripped_path_str))

    return r


async def _deletable_choices(latest_revision_dir: pathlib.Path, target_dirs: set[pathlib.Path]) -> Any:
    # This should be -> list[tuple[str, str]], but that causes pyright to complain incorrectly
    # Details in pyright/dist/dist/typeshed-fallback/stubs/WTForms/wtforms/fields/choices.pyi
    # _Choice: TypeAlias = tuple[Any, str] | tuple[Any, str, dict[str, Any]]
    # Then it wants us to use list[_Choice] (= list[tuple[Any, str]])
    # But it says, incorrectly, that list[tuple[str, str]] is not a list[_Choice]
    # This mistake is not made by mypy
    empty_deletable_dirs: list[pathlib.Path] = []
    if latest_revision_dir.exists():
        for d_rel in target_dirs:
            if d_rel == pathlib.Path("."):
                # Disallow deletion of the root directory
                continue
            d_full = latest_revision_dir / d_rel
            if await aiofiles.os.path.isdir(d_full) and not await aiofiles.os.listdir(d_full):
                empty_deletable_dirs.append(d_rel)
    return sorted([(str(p), str(p)) for p in empty_deletable_dirs])


async def _get_page_data(
    project_name: str, version_name: str
) -> tuple[sql.Release, list[pathlib.Path], set[pathlib.Path], list[tuple[str, str]], RCTagAnalysisResult]:
    """Get all the data needed to render the finish page."""
    async with db.session() as data:
        release = await data.release(
            project_name=project_name,
            version=version_name,
            _committee=True,
        ).demand(base.ASFQuartException("Release does not exist", errorcode=404))

    if release.phase != sql.ReleasePhase.RELEASE_PREVIEW:
        raise ValueError("Release is not in preview phase")

    latest_revision_dir = util.release_directory(release)
    source_files_rel, target_dirs = await _sources_and_targets(latest_revision_dir)
    deletable_dirs = await _deletable_choices(latest_revision_dir, target_dirs)
    rc_analysis_result = await _analyse_rc_tags(latest_revision_dir)

    return release, source_files_rel, target_dirs, deletable_dirs, rc_analysis_result


def _render_delete_directory_form(deletable_dirs: list[tuple[str, str]]) -> htm.Element:
    """Render the delete directory form."""
    section = htm.Block()

    section.h2["Delete an empty directory"]

    form.render_block(
        section,
        shared.finish.DeleteEmptyDirectoryForm,
        defaults={"directory_to_delete": deletable_dirs},
        submit_label="Delete empty directory",
        submit_classes="btn-danger",
        form_classes=".mb-4",
    )

    return section.collect()


def _render_move_section(max_files_to_show: int = 10) -> htm.Element:
    """Render the move files section with JavaScript interaction."""
    section = htm.Block()

    section.h2["Move items to a different directory"]
    section.p[
        "You may ",
        htm.strong["optionally"],
        " move files between your directories here if you want change their location for the final release. "
        "Note that files with associated metadata (e.g. ",
        htm.code[".asc"],
        " or ",
        htm.code[".sha512"],
        " files) are treated as a single unit and will be moved together if any one of them is selected for movement.",
    ]

    section.append(htm.div("#move-error-alert.alert.alert-danger.d-none", role="alert", **{"aria-live": "assertive"}))

    left_card = htm.Block(htm.div, classes=".card.mb-4")
    left_card.div(".card-header.bg-light")[htm.h3(".mb-0")["Select items to move"]]
    left_card.div(".card-body")[
        htpy.input(
            "#file-filter.form-control.mb-2",
            type="text",
            placeholder="Search for an item to move...",
        ),
        htm.table(".table.table-sm.table-striped.border.mt-3")[htm.tbody("#file-list-table-body")],
        htm.div("#file-list-more-info.text-muted.small.mt-1"),
        htpy.button(
            "#select-files-toggle-button.btn.btn-outline-secondary.w-100.mt-2",
            type="button",
        )["Select these files"],
    ]

    right_card = htm.Block(htm.div, classes=".card.mb-4")
    right_card.div(".card-header.bg-light")[
        htm.h3(".mb-0")[htm.span("#selected-file-name-title")["Select a destination for the file"]]
    ]
    right_card.div(".card-body")[
        htpy.input(
            "#dir-filter-input.form-control.mb-2",
            type="text",
            placeholder="Search for a directory to move to...",
        ),
        htm.table(".table.table-sm.table-striped.border.mt-3")[htm.tbody("#dir-list-table-body")],
        htm.div("#dir-list-more-info.text-muted.small.mt-1"),
    ]

    section.form(".atr-canary")[
        htm.div(".row")[
            htm.div(".col-lg-6")[left_card.collect()],
            htm.div(".col-lg-6")[right_card.collect()],
        ],
        htm.div(".mb-3")[
            htpy.label(".form-label", for_="maxFilesInput")["Items to show per list:"],
            htpy.input(
                "#max-files-input.form-control.form-control-sm.w-25",
                type="number",
                value=str(max_files_to_show),
                min="1",
            ),
        ],
        htm.div("#current-move-selection-info.text-muted")["Please select a file and a destination."],
        htm.div[htpy.button("#confirm-move-button.btn.btn-success.mt-2", type="button")["Move to selected directory"]],
    ]

    return section.collect()


async def _render_page(
    release: sql.Release,
    source_files_rel: list,
    target_dirs: set,
    deletable_dirs: list[tuple[str, str]],
    rc_analysis: RCTagAnalysisResult,
) -> str:
    """Render the finish page using htm.py."""
    page = htm.Block()

    shared.distribution.html_nav(
        page,
        back_url=util.as_url(root.index),
        back_anchor="Select a release",
        phase="FINISH",
    )

    # Page heading
    page.h1[
        "Finish ",
        htm.strong[release.project.short_display_name],
        " ",
        htm.em[release.version],
    ]

    # Release info card
    page.append(_render_release_card(release))

    # Information paragraph
    page.p[
        "During this phase you should distribute release artifacts to your package distribution networks "
        "such as Maven Central, PyPI, or Docker Hub."
    ]

    # TODO alert
    page.append(_render_todo_alert(release))

    # Move files section
    page.append(_render_move_section(max_files_to_show=10))

    # Delete directory form
    if deletable_dirs:
        page.append(_render_delete_directory_form(deletable_dirs))

    # Remove RC tags section
    page.append(_render_rc_tags_section(rc_analysis))

    # Custom styles
    page_styles = """
        .page-file-select-text {
            vertical-align: middle;
            margin-left: 8px;
        }
        .page-table-button-cell {
            width: 1%;
            white-space: nowrap;
            vertical-align: middle;
        }
        .page-table-path-cell {
            vertical-align: middle;
        }
        .page-item-selected td {
            background-color: #e9ecef;
            font-weight: 500;
        }
        .page-table-row-interactive {
            height: 52px;
        }
        .page-extra-muted {
            color: #aaaaaa;
        }
    """
    page.style[markupsafe.Markup(page_styles)]

    # JavaScript data
    # TODO: Add htm.script
    csrf_token = utils.generate_csrf()
    page.append(
        htpy.script(id="file-data", type="application/json")[
            markupsafe.Markup(json.dumps([str(f) for f in sorted(source_files_rel)]))
        ]
    )
    page.append(
        htpy.script(id="dir-data", type="application/json")[
            markupsafe.Markup(json.dumps(sorted([str(d) for d in target_dirs])))
        ]
    )
    page.append(
        htpy.script(
            id="main-script-data",
            src=util.static_url("js/finish-selected-move.js"),
            **{"data-csrf-token": csrf_token},
        )[""]
    )

    content = page.collect()

    return await template.blank(
        title=f"Finish {release.project.display_name} {release.version} ~ ATR",
        description=f"Finish {release.project.display_name} {release.version} as a release preview.",
        content=content,
    )


def _render_rc_tags_section(rc_analysis: RCTagAnalysisResult) -> htm.Element:
    """Render the remove RC tags section."""
    section = htm.Block()

    section.h2["Remove release candidate tags"]

    if rc_analysis.affected_count > 0:
        section.div(".alert.alert-info.mb-3")[
            htm.p(".mb-3.fw-semibold")[
                f"{rc_analysis.affected_count} / {rc_analysis.total_paths} paths would be affected by RC tag removal."
            ],
            _render_rc_preview_table(rc_analysis.affected_paths_preview) if rc_analysis.affected_paths_preview else "",
        ]

        form.render_block(
            section,
            shared.finish.RemoveRCTagsForm,
            submit_label="Remove RC tags",
            submit_classes="btn-warning",
            form_classes=".mb-4.atr-canary",
        )
    else:
        section.p["No paths with RC tags found to remove."]

    return section.collect()


def _render_rc_preview_table(affected_paths: list[tuple[str, str]]) -> htm.Element:
    """Render the RC tags preview table."""
    rows = [htm.tr[htm.td[original], htm.td[stripped]] for original, stripped in affected_paths]

    return htm.div[
        htm.p(".mb-2")["Preview of changes:"],
        htm.table(".table.table-sm.table-striped.border.mt-3")[htm.tbody[rows]],
    ]


def _render_release_card(release: sql.Release) -> htm.Element:
    """Render the release information card."""
    card = htm.div(".card.mb-4.shadow-sm", id=release.name)[
        htm.div(".card-header.bg-light")[htm.h3(".card-title.mb-0")["About this release preview"]],
        htm.div(".card-body")[
            htm.div(".d-flex.flex-wrap.gap-3.pb-3.mb-3.border-bottom.text-secondary.fs-6")[
                htm.span(".page-preview-meta-item")[f"Revision: {release.latest_revision_number}"],
                htm.span(".page-preview-meta-item")[f"Created: {release.created.strftime('%Y-%m-%d %H:%M:%S UTC')}"],
            ],
            htm.div[
                htm.a(
                    ".btn.btn-primary.me-2",
                    title="Download all files",
                    href=util.as_url(
                        download.all_selected,
                        project_name=release.project.name,
                        version_name=release.version,
                    ),
                )[
                    htpy.i(".bi.bi-download"),
                    " Download all files",
                ],
                htm.a(
                    ".btn.btn-secondary.me-2",
                    title=f"Show files for {release.name}",
                    href=util.as_url(
                        preview.view,
                        project_name=release.project.name,
                        version_name=release.version,
                    ),
                )[
                    htpy.i(".bi.bi-archive"),
                    " Show files",
                ],
                htm.a(
                    ".btn.btn-secondary.me-2",
                    title=f"Show revisions for {release.name}",
                    href=util.as_url(
                        revisions.selected,
                        project_name=release.project.name,
                        version_name=release.version,
                    ),
                )[
                    htpy.i(".bi.bi-clock-history"),
                    " Show revisions",
                ],
                htm.a(
                    ".btn.btn-success",
                    title=f"Announce and distribute {release.name}",
                    href=util.as_url(
                        announce.selected,
                        project_name=release.project.name,
                        version_name=release.version,
                    ),
                )[
                    htpy.i(".bi.bi-check-circle"),
                    " Announce and distribute",
                ],
            ],
        ],
    ]
    return card


def _render_todo_alert(release: sql.Release) -> htm.Element:
    """Render the TODO alert about distribution tools."""
    return htm.div(".alert.alert-warning.mb-4", role="alert")[
        htm.p(".fw-semibold.mb-1")["TODO"],
        htm.p(".mb-1")[
            "We plan to add tools to help release managers to distribute release artifacts on distribution networks. "
            "Currently you must do this manually. Once you've distributed your release artifacts, you can ",
            htm.a(
                href=util.as_url(
                    distribution.record,
                    project=release.project.name,
                    version=release.version,
                )
            )["record them on the ATR"],
            ".",
        ],
    ]


async def _sources_and_targets(latest_revision_dir: pathlib.Path) -> tuple[list[pathlib.Path], set[pathlib.Path]]:
    source_items_rel: list[pathlib.Path] = []
    target_dirs: set[pathlib.Path] = {pathlib.Path(".")}

    async for item_rel_path in util.paths_recursive_all(latest_revision_dir):
        current_parent = item_rel_path.parent
        source_items_rel.append(item_rel_path)

        while True:
            target_dirs.add(current_parent)
            if current_parent == pathlib.Path("."):
                break
            current_parent = current_parent.parent

        item_abs_path = latest_revision_dir / item_rel_path
        if await aiofiles.os.path.isfile(item_abs_path):
            pass
        elif await aiofiles.os.path.isdir(item_abs_path):
            target_dirs.add(item_rel_path)

    return source_items_rel, target_dirs
