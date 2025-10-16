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
import pathlib
from typing import TYPE_CHECKING

import asfquart.base as base
import htpy
import markupsafe
import quart

import atr.db as db
import atr.forms as forms
import atr.htm as htm
import atr.log as log
import atr.models.results as results
import atr.models.sql as sql
import atr.route as route
import atr.sbom as sbom
import atr.storage as storage
import atr.template as template
import atr.util as util

if TYPE_CHECKING:
    import werkzeug.wrappers.response as response


@route.committer("/sbom/augment/<project_name>/<version_name>/<path:file_path>", methods=["POST"])
async def augment(
    session: route.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response:
    """Augment a CycloneDX SBOM file."""
    await session.check_access(project_name)

    await util.validate_empty_form()
    rel_path = pathlib.Path(file_path)

    # Check that the file is a .cdx.json archive before creating a revision
    if not (file_path.endswith(".cdx.json")):
        raise base.ASFQuartException("SBOM augmentation is only supported for .cdx.json files", errorcode=400)

    try:
        async with db.session() as data:
            release = await data.release(project_name=project_name, version=version_name).demand(
                RuntimeError("Release does not exist for new revision creation")
            )
            revision_number = release.latest_revision_number
            if revision_number is None:
                raise RuntimeError("No revision number found for new revision creation")
            log.info(f"Augmenting SBOM for {project_name} {version_name} {revision_number} {rel_path}")
        async with storage.write_as_project_committee_member(project_name) as wacm:
            sbom_task = await wacm.sbom.augment_cyclonedx(project_name, version_name, revision_number, rel_path)

    except Exception as e:
        log.exception("Error augmenting SBOM:")
        await quart.flash(f"Error augmenting SBOM: {e!s}", "error")
        return await session.redirect(
            report,
            project=project_name,
            version=version_name,
            file_path=str(rel_path),
        )

    return await session.redirect(
        report,
        success=f"SBOM augmentation task queued for {rel_path.name} (task ID: {util.unwrap(sbom_task.id)})",
        project=project_name,
        version=version_name,
        file_path=str(rel_path),
    )


@route.committer("/sbom/report/<project>/<version>/<path:file_path>")
async def report(session: route.CommitterSession, project: str, version: str, file_path: str) -> str:
    await session.check_access(project)
    await session.release(project, version)
    async with db.session() as data:
        via = sql.validate_instrumented_attribute
        # TODO: Abstract this code and the sbomtool.MissingAdapter validators
        tasks = (
            await data.task(
                project_name=project,
                version_name=version,
                task_type=sql.TaskType.SBOM_TOOL_SCORE,
                status=sql.TaskStatus.COMPLETED,
                primary_rel_path=file_path,
            )
            .order_by(sql.sqlmodel.desc(via(sql.Task.completed)))
            .all()
        )

    block = htm.Block()
    block.h1["SBOM report"]

    if not tasks:
        # TODO: Show task if the score is being computed
        block.p["No SBOM score found."]
        return await template.blank("SBOM report", content=block.collect())

    task_result = tasks[0].result
    if not isinstance(task_result, results.SBOMToolScore):
        raise base.ASFQuartException("Invalid SBOM score result", errorcode=500)
    warnings = [sbom.MissingAdapter.validate_python(json.loads(w)) for w in task_result.warnings]
    errors = [sbom.MissingAdapter.validate_python(json.loads(e)) for e in task_result.errors]

    block.p[
        """This is a report by the sbomtool, for debugging and
        informational purposes. Please use it only as an approximate
        guideline to the quality of your SBOM file. It checks for NTIA 2021
        minimum data field conformance."""
    ]
    block.p["This report is for revision ", htpy.code[task_result.revision_number], "."]

    empty_form = await forms.Empty.create_form()
    # TODO: Show the status if the task to augment the SBOM is still running
    # TODO: Add a field to the SBOM to show that it's been augmented
    # And then don't allow it to be augmented again
    action = util.as_url(
        augment,
        project_name=project,
        version_name=version,
        file_path=file_path,
    )
    block.append(
        htpy.form("", action=action, method="post")[
            markupsafe.Markup(str(empty_form.hidden_tag())),
            htpy.button(".btn.btn-primary", type="submit")["Augment SBOM"],
        ]
    )

    if warnings:
        block.h2["Warnings"]
        _missing_table(block, warnings)

    if errors:
        block.h2["Errors"]
        _missing_table(block, errors)

    if not (warnings or errors):
        block.h2["Results"]
        block.p["No NTIA 2021 minimum data field conformance warnings or errors found."]

    outdated = None
    if task_result.outdated:
        outdated = sbom.OutdatedAdapter.validate_python(json.loads(task_result.outdated))
    block.h2["Outdated tool"]
    if outdated:
        if outdated.kind == "tool":
            block.p[
                f"""The CycloneDX Maven Plugin is outdated. The used version is
                {outdated.used_version} and the available version is
                {outdated.available_version}."""
            ]
        else:
            block.p[
                f"""There was a problem with the SBOM detected when trying to
                determine if the CycloneDX Maven Plugin is outdated:
                {outdated.kind.upper()}."""
            ]
    else:
        block.p["No outdated tool found."]

    block.h2["CycloneDX CLI validation errors"]
    if task_result.cli_errors:
        block.pre["\n".join(task_result.cli_errors)]
    else:
        block.p["No CycloneDX CLI validation errors found."]

    return await template.blank("SBOM report", content=block.collect())


def _missing_table(block: htm.Block, items: list[sbom.Missing]) -> None:
    warning_rows = [
        htpy.tr[
            htpy.td[kind.upper()],
            htpy.td[prop],
            htpy.td[str(count)],
        ]
        for kind, prop, count in _missing_tally(items)
    ]
    block.table(".table.table-sm.table-bordered.table-striped")[
        htpy.thead[htpy.tr[htpy.th["Kind"], htpy.th["Property"], htpy.th["Count"]]],
        htpy.tbody[*warning_rows],
    ]


def _missing_tally(items: list[sbom.Missing]) -> list[tuple[str, str, int]]:
    counts: dict[tuple[str, str], int] = {}
    for item in items:
        key = (getattr(item, "kind", ""), getattr(getattr(item, "property", None), "name", ""))
        counts[key] = counts.get(key, 0) + 1
    return sorted(
        [(kind, prop, count) for (kind, prop), count in counts.items()],
        key=lambda kv: (kv[0], kv[1]),
    )
