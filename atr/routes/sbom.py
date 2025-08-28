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
        block.p["No SBOM score found."]
        return await template.blank("SBOM report", content=block.collect())

    task_result = tasks[0].result
    if not isinstance(task_result, results.SBOMToolScoreResult):
        raise base.ASFQuartException("Invalid SBOM score result", errorcode=500)
    warnings = task_result.warnings
    errors = task_result.errors

    block.p[
        """This is a report by the sbomtool, for debugging and
        informational purposes. Please use it only as an approximate
        guideline to the quality of your SBOM file. It currently
        checks for NTIA 2021 minimum data field conformance."""
    ]

    if warnings:
        block.h2["Warnings"]
        block.ul[*[htpy.li[w] for w in warnings]]

    if errors:
        block.h2["Errors"]
        block.ul[*[htpy.li[e] for e in errors]]

    return await template.blank("SBOM report", content=block.collect())
