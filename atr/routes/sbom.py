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
from typing import TYPE_CHECKING, Any

import asfquart.base as base
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
    import collections.abc

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

        osv_tasks = (
            await data.task(
                project_name=project,
                version_name=version,
                task_type=sql.TaskType.SBOM_OSV_SCAN,
                primary_rel_path=file_path,
            )
            .order_by(sql.sqlmodel.desc(via(sql.Task.added)))
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
    warnings = [sbom.models.conformance.MissingAdapter.validate_python(json.loads(w)) for w in task_result.warnings]
    errors = [sbom.models.conformance.MissingAdapter.validate_python(json.loads(e)) for e in task_result.errors]

    block.p[
        """This is a report by the ATR SBOM tool, for debugging and
        informational purposes. Please use it only as an approximate
        guideline to the quality of your SBOM file."""
    ]
    block.p["This report is for revision ", htm.code[task_result.revision_number], "."]

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
        htm.form("", action=action, method="post")[
            markupsafe.Markup(str(empty_form.hidden_tag())),
            htm.button(".btn.btn-primary", type="submit")["Augment SBOM"],
        ]
    )

    if warnings:
        block.h2["Warnings"]
        _missing_table(block, warnings)

    if errors:
        block.h2["Errors"]
        _missing_table(block, errors)

    if not (warnings or errors):
        block.h2["Conformance report"]
        block.p["No NTIA 2021 minimum data field conformance warnings or errors found."]

    block.h2["Vulnerability scan"]
    _vulnerability_scan_section(block, project, version, file_path, task_result.revision_number, osv_tasks, empty_form)

    block.h2["Outdated tool"]
    outdated = None
    if task_result.outdated:
        outdated = sbom.models.maven.OutdatedAdapter.validate_python(json.loads(task_result.outdated))
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


@route.committer("/sbom/scan/<project_name>/<version_name>/<path:file_path>", methods=["POST"])
async def scan(
    session: route.CommitterSession, project_name: str, version_name: str, file_path: str
) -> response.Response:
    """Scan a CycloneDX SBOM file for vulnerabilities using OSV."""
    await session.check_access(project_name)

    await util.validate_empty_form()
    rel_path = pathlib.Path(file_path)

    if not (file_path.endswith(".cdx.json")):
        raise base.ASFQuartException("OSV scanning is only supported for .cdx.json files", errorcode=400)

    try:
        async with db.session() as data:
            release = await data.release(project_name=project_name, version=version_name).demand(
                RuntimeError("Release does not exist for OSV scan")
            )
            revision_number = release.latest_revision_number
            if revision_number is None:
                raise RuntimeError("No revision number found for OSV scan")
            log.info(f"Starting OSV scan for {project_name} {version_name} {revision_number} {rel_path}")
        async with storage.write_as_project_committee_member(project_name) as wacm:
            sbom_task = await wacm.sbom.osv_scan_cyclonedx(project_name, version_name, revision_number, rel_path)

    except Exception as e:
        log.exception("Error starting OSV scan:")
        await quart.flash(f"Error starting OSV scan: {e!s}", "error")
        return await session.redirect(
            report,
            project=project_name,
            version=version_name,
            file_path=str(rel_path),
        )

    return await session.redirect(
        report,
        success=f"OSV vulnerability scan queued for {rel_path.name} (task ID: {util.unwrap(sbom_task.id)})",
        project=project_name,
        version=version_name,
        file_path=str(rel_path),
    )


def _extract_vulnerability_severity(vuln: dict[str, Any]) -> str:
    """Extract severity information from vulnerability data."""
    db_specific = vuln.get("database_specific", {})
    if "severity" in db_specific:
        return db_specific["severity"]

    severity_data = vuln.get("severity", [])
    if severity_data and isinstance(severity_data, list):
        first_severity = severity_data[0]
        if isinstance(first_severity, dict) and ("type" in first_severity):
            return first_severity["type"]

    return "Unknown"


def _missing_table(block: htm.Block, items: list[sbom.models.conformance.Missing]) -> None:
    warning_rows = [
        htm.tr[
            htm.td[kind.upper()],
            htm.td[prop],
            htm.td[str(count)],
        ]
        for kind, prop, count in _missing_tally(items)
    ]
    block.table(".table.table-sm.table-bordered.table-striped")[
        htm.thead[htm.tr[htm.th["Kind"], htm.th["Property"], htm.th["Count"]]],
        htm.tbody[*warning_rows],
    ]


def _missing_tally(items: list[sbom.models.conformance.Missing]) -> list[tuple[str, str, int]]:
    counts: dict[tuple[str, str], int] = {}
    for item in items:
        key = (getattr(item, "kind", ""), getattr(getattr(item, "property", None), "name", ""))
        counts[key] = counts.get(key, 0) + 1
    return sorted(
        [(kind, prop, count) for (kind, prop), count in counts.items()],
        key=lambda kv: (kv[0], kv[1]),
    )


def _vulnerability_component_details(block: htm.Block, component: results.OSVComponent) -> None:
    details_content = []
    summary_element = htm.summary[
        htm.span(".badge.bg-danger.me-2.font-monospace")[str(len(component.vulnerabilities))],
        htm.strong[component.purl],
    ]
    details_content.append(summary_element)

    for vuln in component.vulnerabilities:
        vuln_id = vuln.get("id", "Unknown")
        vuln_summary = vuln.get("summary", "No summary available")
        vuln_modified = vuln.get("modified", "Unknown")
        vuln_severity = _extract_vulnerability_severity(vuln)

        vuln_header = [htm.strong(".me-2")[vuln_id]]
        if vuln_severity != "Unknown":
            vuln_header.append(htm.span(".badge.bg-warning.text-dark")[vuln_severity])

        vuln_div = htm.div(".ms-3.mb-3.border-start.border-warning.border-3.ps-3")[
            htm.div(".d-flex.align-items-center.mb-2")[*vuln_header],
            htm.p(".mb-1")[vuln_summary],
            htm.div(".text-muted.small")[
                "Last modified: ",
                vuln_modified,
            ],
            htm.div(".mt-2.text-muted")[vuln.get("details", "No additional details available.")],
        ]
        details_content.append(vuln_div)

    block.append(htm.details(".mb-3.rounded")[*details_content])


def _vulnerability_scan_button(
    block: htm.Block, project: str, version: str, file_path: str, empty_form: forms.Empty
) -> None:
    block.p["No vulnerability scan has been performed for this revision."]

    action = util.as_url(
        scan,
        project_name=project,
        version_name=version,
        file_path=file_path,
    )
    block.append(
        htm.form("", action=action, method="post")[
            markupsafe.Markup(str(empty_form.hidden_tag())),
            htm.button(".btn.btn-primary", type="submit")["Scan file"],
        ]
    )


def _vulnerability_scan_find_completed_task(
    osv_tasks: collections.abc.Sequence[sql.Task], revision_number: str
) -> sql.Task | None:
    """Find the most recent completed OSV scan task for the given revision."""
    for task in osv_tasks:
        if task.status == sql.TaskStatus.COMPLETED and (task.result is not None):
            task_result = task.result
            if isinstance(task_result, results.SBOMOSVScan) and task_result.revision_number == revision_number:
                return task
    return None


def _vulnerability_scan_find_in_progress_task(
    osv_tasks: collections.abc.Sequence[sql.Task], revision_number: str
) -> sql.Task | None:
    """Find the most recent in-progress OSV scan task for the given revision."""
    for task in osv_tasks:
        if task.revision_number == revision_number:
            if task.status in (sql.TaskStatus.QUEUED, sql.TaskStatus.ACTIVE, sql.TaskStatus.FAILED):
                return task
    return None


def _vulnerability_scan_results(block: htm.Block, task: sql.Task) -> None:
    task_result = task.result
    if not isinstance(task_result, results.SBOMOSVScan):
        block.p["Invalid scan result format."]
        return

    components = task_result.components
    ignored_count = task_result.ignored_count

    if not components:
        block.p["No vulnerabilities found."]
        if ignored_count > 0:
            component_word = "component" if (ignored_count == 1) else "components"
            block.p[f"{ignored_count} {component_word} were ignored due to missing PURL or version information."]
        return

    block.p[f"Found vulnerabilities in {len(components)} components:"]

    for component in components:
        _vulnerability_component_details(block, component)

    if ignored_count > 0:
        component_word = "component" if (ignored_count == 1) else "components"
        block.p[f"{ignored_count} {component_word} were ignored due to missing PURL or version information."]


def _vulnerability_scan_section(
    block: htm.Block,
    project: str,
    version: str,
    file_path: str,
    revision_number: str,
    osv_tasks: collections.abc.Sequence[sql.Task],
    empty_form: forms.Empty,
) -> None:
    """Display the vulnerability scan section based on task status."""
    completed_task = _vulnerability_scan_find_completed_task(osv_tasks, revision_number)

    if completed_task is not None:
        _vulnerability_scan_results(block, completed_task)
        return

    in_progress_task = _vulnerability_scan_find_in_progress_task(osv_tasks, revision_number)

    if in_progress_task is not None:
        _vulnerability_scan_status(block, in_progress_task, project, version, file_path, empty_form)
    else:
        _vulnerability_scan_button(block, project, version, file_path, empty_form)


def _vulnerability_scan_status(
    block: htm.Block,
    task: sql.Task,
    project: str,
    version: str,
    file_path: str,
    empty_form: forms.Empty,
) -> None:
    status_text = task.status.value.replace("_", " ").capitalize()
    block.p[f"Vulnerability scan is currently {status_text.lower()}."]
    block.p["Task ID: ", htm.code[str(task.id)]]
    if (task.status == sql.TaskStatus.FAILED) and (task.error is not None):
        block.p[
            "Task reported an error: ",
            htm.code[task.error],
            ". Additional details are unavailable from ATR.",
        ]
        _vulnerability_scan_button(block, project, version, file_path, empty_form)
