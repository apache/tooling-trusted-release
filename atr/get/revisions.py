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

import asyncio
import pathlib

import aiofiles.os
import asfquart.base as base
import sqlalchemy.orm as orm
import sqlmodel

import atr.blueprints.get as get
import atr.db as db
import atr.form as form
import atr.get.compose as compose
import atr.get.finish as finish
import atr.get.root as root
import atr.htm as htm
import atr.models.schema as schema
import atr.models.sql as sql
import atr.shared as shared
import atr.template as template
import atr.util as util
import atr.web as web


class FilesDiff(schema.Strict):
    added: list[pathlib.Path]
    removed: list[pathlib.Path]
    modified: list[pathlib.Path]


@get.committer("/revisions/<project_name>/<version_name>")
async def selected(session: web.Committer, project_name: str, version_name: str) -> str:
    """Show the revision history for a release candidate draft or release preview."""
    await session.check_access(project_name)

    try:
        release = await session.release(project_name, version_name)
        phase_key = "draft"
    except base.ASFQuartException:
        release = await session.release(project_name, version_name, phase=sql.ReleasePhase.RELEASE_PREVIEW)
        phase_key = "preview"
    release_dir = util.release_directory_base(release)

    # Determine the current revision
    latest_revision_number = release.latest_revision_number
    if latest_revision_number is None:
        # TODO: Set an error message, and redirect to the release page?
        pass

    # Oldest to newest, to build diffs relative to previous revision
    async with db.session() as data_for_revisions:
        revisions_stmt = (
            sqlmodel.select(sql.Revision)
            .where(sql.Revision.release_name == release.name)
            .order_by(sql.validate_instrumented_attribute(sql.Revision.seq))
            .options(orm.selectinload(sql.validate_instrumented_attribute(sql.Revision.parent)))
        )
        revisions_result = await data_for_revisions.execute(revisions_stmt)
        revisions_list: list[sql.Revision] = list(revisions_result.scalars().all())

    revision_history = []
    loop_prev_revision_files: set[pathlib.Path] | None = None
    loop_prev_revision_number: str | None = None
    for current_db_revision in revisions_list:
        current_files_for_diff, files_diff_for_current = await _revision_files_diff(
            revision_number=current_db_revision.number,
            release_dir=release_dir,
            prev_revision_files=loop_prev_revision_files,
            prev_revision_number=loop_prev_revision_number,
        )
        revision_history.append((current_db_revision, files_diff_for_current))
        loop_prev_revision_files = current_files_for_diff
        loop_prev_revision_number = current_db_revision.number

    content = await _render_page(
        release,
        phase_key,
        list(reversed(revision_history)),
        latest_revision_number,
        project_name,
        version_name,
    )

    return await template.blank(
        title=f"Revisions of {release.short_display_name}",
        content=content,
    )


def _render_back_link(release: sql.Release, phase_key: str) -> htm.Element:
    if phase_key == "draft":
        back_url = util.as_url(compose.selected, project_name=release.project.name, version_name=release.version)
        return htm.a(".atr-back-link", href=back_url)[f"← Back to Compose {release.short_display_name}"]
    elif phase_key == "preview":
        back_url = util.as_url(finish.selected, project_name=release.project.name, version_name=release.version)
        return htm.a(".atr-back-link", href=back_url)[f"← Back to Finish {release.short_display_name}"]
    else:
        return htm.a(".atr-back-link", href=util.as_url(root.index))["← Back to Select a release"]


def _render_files_diff(body: htm.Block, files_diff: "FilesDiff") -> None:
    if not (files_diff.added or files_diff.removed or files_diff.modified):
        body.p(".fst-italic.text-muted.mt-2")["No file changes detected in this revision."]
        return

    if files_diff.added:
        body.h3(".fs-6.fw-semibold.mt-3.atr-sans")[
            "Added files ",
            htm.span(".font-monospace.fw-normal")[f"({len(files_diff.added)})"],
        ]
        with body.block(htm.ul, classes=".list-group.list-group-flush.mb-2") as ul:
            for file in files_diff.added:
                ul.li(".list-group-item.list-group-item-success.py-1.px-3.small.rounded-2")[str(file)]

    if files_diff.removed:
        body.h3(".fs-6.fw-semibold.mt-3.atr-sans")[
            "Removed files ",
            htm.span(".font-monospace.fw-normal")[f"({len(files_diff.removed)})"],
        ]
        with body.block(htm.ul, classes=".list-group.list-group-flush.mb-2") as ul:
            for file in files_diff.removed:
                ul.li(".list-group-item.list-group-item-danger.py-1.px-3.small.rounded-2")[str(file)]

    if files_diff.modified:
        body.h3(".fs-6.fw-semibold.mt-3.atr-sans")[
            "Modified files ",
            htm.span(".font-monospace.fw-normal")[f"({len(files_diff.modified)})"],
        ]
        with body.block(htm.ul, classes=".list-group.list-group-flush.mb-2") as ul:
            for file in files_diff.modified:
                ul.li(".list-group-item.list-group-item-warning.py-1.px-3.small.rounded-2")[str(file)]


async def _render_page(
    release: sql.Release,
    phase_key: str,
    revision_history: list[tuple[sql.Revision, "FilesDiff"]],
    latest_revision_number: str | None,
    project_name: str,
    version_name: str,
) -> htm.Element:
    page = htm.Block()

    page.p(".d-flex.justify-content-between.align-items-center")[
        _render_back_link(release, phase_key),
        _render_phase_indicator(phase_key),
    ]

    page.h1[
        "Revisions of ",
        htm.strong[release.project.short_display_name],
        " ",
        htm.em[release.version],
    ]

    if revision_history:
        for revision, files_diff in revision_history:
            _render_revision_card(
                page, revision, files_diff, latest_revision_number, phase_key, project_name, version_name
            )
    else:
        page.div(".alert.alert-info")["No revision history found for this candidate draft."]

    return page.collect()


def _render_phase_indicator(phase_key: str) -> htm.Element:
    span = htm.Block(htm.span)

    if phase_key == "draft":
        span.strong(".atr-phase-one.atr-phase-symbol")["①"]
        span.span(".atr-phase-one.atr-phase-label")["COMPOSE"]
        span.span(".atr-phase-arrow")["→"]
        span.span(".atr-phase-symbol-other")["②"]
        span.span(".atr-phase-arrow")["→"]
        span.span(".atr-phase-symbol-other")["③"]
    elif phase_key == "preview":
        span.span(".atr-phase-symbol-other")["①"]
        span.span(".atr-phase-arrow")["→"]
        span.span(".atr-phase-symbol-other")["②"]
        span.span(".atr-phase-arrow")["→"]
        span.strong(".atr-phase-three.atr-phase-symbol")["③"]
        span.span(".atr-phase-three.atr-phase-label")["FINISH"]

    return span.collect(separator=" ")


def _render_revision_actions(body: htm.Block, revision: sql.Revision, project_name: str, version_name: str) -> None:
    body.h3(".fs-6.fw-semibold.mt-3.atr-sans")["Actions"]
    body.div(".mt-3")[
        form.render(
            model_cls=shared.revisions.SetRevisionForm,
            form_classes="",
            submit_classes="btn-sm btn-outline-danger",
            submit_label="Create a new revision from this one",
            defaults={"revision_number": revision.number},
            empty=True,
        )
    ]


def _render_revision_card(
    page: htm.Block,
    revision: sql.Revision,
    files_diff: "FilesDiff",
    latest_revision_number: str | None,
    phase_key: str,
    project_name: str,
    version_name: str,
) -> None:
    with page.block(htm.div, classes=".card.mb-3") as card:
        card.div(".card-header.d-flex.justify-content-between.align-items-center")[
            _render_revision_header(revision, latest_revision_number),
            _render_revision_timestamp(revision),
        ]
        with card.block(htm.div, classes=".card-body") as card_body:
            if revision.description:
                card_body.p(".mb-2")[htm.strong[revision.description]]

            if revision.parent:
                card_body.p(".small.text-muted.mb-2")[
                    "Changes from ",
                    htm.a(href=f"#{revision.parent.number}", title=f"Revision {revision.parent.number}")[
                        "previous revision"
                    ],
                    ":",
                ]
            else:
                card_body.p(".small.text-muted.mb-2")["Initial revision"]

            _render_files_diff(card_body, files_diff)

            is_draft = phase_key == "draft"
            revision_is_preview = revision.phase.value.lower() == "release_preview"
            if (revision.number != latest_revision_number) and (is_draft or revision_is_preview):
                _render_revision_actions(card_body, revision, project_name, version_name)


def _render_revision_header(revision: sql.Revision, latest_revision_number: str | None) -> htm.Element:
    revision_phase_key = revision.phase.value.lower().split("_")[-1]
    badges = [
        htm.span(".badge.bg-secondary.ms-2")[revision_phase_key.upper()],
    ]
    if revision.number == latest_revision_number:
        badges.append(htm.span(".badge.bg-primary.ms-2")["Current"])

    return htm.h2(".fs-6.my-2.mx-0.p-0.border-0.atr-sans")[
        htm.a(".fw-bold.text-decoration-none.text-body", href=f"#{revision.number}")[revision.number],
        *badges,
    ]


def _render_revision_timestamp(revision: sql.Revision) -> htm.Element:
    if revision.created:
        timestamp = revision.created.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        timestamp = "Invalid timestamp"

    return htm.span(".fs-6.text-muted")[f"{timestamp} by {revision.asfuid}"]


async def _revision_files_diff(
    revision_number: str,
    release_dir: pathlib.Path,
    prev_revision_files: set[pathlib.Path] | None,
    prev_revision_number: str | None,
) -> tuple[set[pathlib.Path], FilesDiff]:
    """Process a single revision and calculate its diff from the previous."""
    latest_revision_dir = release_dir / revision_number
    latest_revision_files = {path async for path in util.paths_recursive(latest_revision_dir)}

    added_files: set[pathlib.Path] = set()
    removed_files: set[pathlib.Path] = set()
    modified_files: set[pathlib.Path] = set()

    if (prev_revision_files is not None) and (prev_revision_number is not None):
        added_files = latest_revision_files - prev_revision_files
        removed_files = prev_revision_files - latest_revision_files
        common_files = latest_revision_files & prev_revision_files

        # Check modification times for common files
        parent_revision_dir = release_dir / prev_revision_number
        mtime_tasks = []
        for common_file in common_files:

            async def check_mtime(file_path: pathlib.Path) -> tuple[pathlib.Path, bool]:
                try:
                    parent_mtime = await aiofiles.os.path.getmtime(parent_revision_dir / file_path)
                    latest_mtime = await aiofiles.os.path.getmtime(latest_revision_dir / file_path)
                    return file_path, parent_mtime != latest_mtime
                except OSError:
                    # Treat errors as modified
                    return file_path, True

            mtime_tasks.append(check_mtime(common_file))

        results = await asyncio.gather(*mtime_tasks)
        modified_files = {f for f, modified in results if modified}
    else:
        # First revision, all files are considered added
        added_files = latest_revision_files

    files_diff = FilesDiff(
        added=sorted(list(added_files)),
        removed=sorted(list(removed_files)),
        modified=sorted(list(modified_files)),
    )
    return latest_revision_files, files_diff
