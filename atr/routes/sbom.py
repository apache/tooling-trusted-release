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

import atr.db as db
import atr.htm as htm
import atr.models.results as results
import atr.models.sql as sql
import atr.routes as routes
import atr.template as template


@routes.committer("/sbom/report/<project>/<version>/<path:file_path>")
async def report(session: routes.CommitterSession, project: str, version: str, file_path: str) -> str:
    await session.check_access(project)
    await session.release(project, version)
    async with db.session() as data:
        via = sql.validate_instrumented_attribute
        tasks = (
            await data.task(
                project_name=project,
                version_name=version,
                task_type=sql.TaskType.SBOM_QS_SCORE,
                status=sql.TaskStatus.COMPLETED,
                primary_rel_path=file_path,
            )
            .order_by(sql.sqlmodel.desc(via(sql.Task.completed)))
            .all()
        )
    if not tasks:
        raise base.ASFQuartException("SBOM score not found", errorcode=404)
    task_result = tasks[0].result
    if not isinstance(task_result, results.SBOMQsScoreResult):
        raise base.ASFQuartException("Invalid SBOM score result", errorcode=500)
    report_obj = task_result.report

    block = htm.Block()
    block.h1["SBOM report"]

    summary_tbody = htpy.tbody[
        _tr("Run ID", report_obj.run_id),
        _tr("Timestamp", report_obj.timestamp),
        _tr("Tool", report_obj.creation_info.name),
        _tr("Tool version", report_obj.creation_info.version),
        _tr("Engine version", report_obj.creation_info.scoring_engine_version),
        _tr("Vendor", report_obj.creation_info.vendor),
    ]
    block.h2["Summary"]
    block.table(".table.table-striped.table-bordered")[summary_tbody]

    block.h2["Files"]
    for fr in report_obj.files:
        block.h3[fr.file_name]
        file_tbody = htpy.tbody[
            _tr("Spec", fr.spec),
            _tr("Spec version", fr.spec_version),
            _tr("Format", fr.file_format),
            _tr("Avg score", str(fr.avg_score)),
            _tr("Components", str(fr.num_components)),
            _tr("Creation time", fr.creation_time),
            _tr("Generator", fr.gen_tool_name),
            _tr("Generator version", fr.gen_tool_version),
        ]
        block.table(".table.table-striped.table-bordered")[file_tbody]

        header = htpy.thead[
            htpy.tr[
                htpy.th["Category"],
                htpy.th["Feature"],
                htpy.th["Score"],
                htpy.th["Max"],
                htpy.th["Ignored"],
            ]
        ]
        rows = [
            htpy.tr[
                htpy.td[s.category],
                htpy.td[s.feature],
                htpy.td[str(s.score)],
                htpy.td[str(s.max_score)],
                htpy.td["Yes" if s.ignored else "No"],
            ]
            for s in fr.scores
        ]
        table_block = htm.Block(htpy.table(".table.table-striped.table-bordered"))
        table_block.append(header)
        table_block.append(htpy.tbody[*rows])
        block.append(table_block.collect())

    return await template.blank("SBOM report", content=block.collect())


def _tr(label: str, value: str) -> htpy.Element:
    return htpy.tr[htpy.th[label], htpy.td[value]]
