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

from typing import TYPE_CHECKING

import quart

import atr.blueprints.post as post
import atr.db as db
import atr.get as get
import atr.models.distribution as distribution
import atr.shared as shared
import atr.storage as storage
import atr.web as web

if TYPE_CHECKING:
    import werkzeug.wrappers.response as response


@post.committer("/distribution/delete/<project>/<version>")
async def delete(session: web.Committer, project: str, version: str) -> response.Response:
    form = await shared.distribution.DeleteForm.create_form(data=await quart.request.form)
    dd = distribution.DeleteData.model_validate(form.data)

    # Validate the submitted data, and obtain the committee for its name
    async with db.session() as data:
        release = await data.release(name=dd.release_name).demand(RuntimeError(f"Release {dd.release_name} not found"))
    committee = release.committee
    if committee is None:
        raise RuntimeError(f"Release {dd.release_name} has no committee")

    # Delete the distribution
    async with storage.write_as_committee_member(committee_name=committee.name) as wacm:
        await wacm.distributions.delete_distribution(
            release_name=dd.release_name,
            platform=dd.platform,
            owner_namespace=dd.owner_namespace,
            package=dd.package,
            version=dd.version,
        )
    return await session.redirect(
        get.distribution.list_get,
        project=project,
        version=version,
        success="Distribution deleted",
    )


@post.committer("/distribution/record/<project>/<version>")
async def record_post(session: web.Committer, project: str, version: str) -> str:
    form = await shared.distribution.DistributeForm.create_form(data=await quart.request.form)
    fpv = shared.distribution.FormProjectVersion(form=form, project=project, version=version)
    if await form.validate():
        return await shared.distribution.record_form_process_page(fpv)
    match len(form.errors):
        case 0:
            # Should not happen
            await quart.flash("Ambiguous submission errors", category="warning")
        case 1:
            await quart.flash("There was 1 submission error", category="error")
        case _ as n:
            await quart.flash(f"There were {n} submission errors", category="error")
    return await shared.distribution.record_form_page(fpv)


@post.committer("/distribution/stage/<project>/<version>")
async def stage_post(session: web.Committer, project: str, version: str) -> str:
    form = await shared.distribution.DistributeForm.create_form(data=await quart.request.form)
    fpv = shared.distribution.FormProjectVersion(form=form, project=project, version=version)
    if await form.validate():
        return await shared.distribution.record_form_process_page(fpv, staging=True)
    match len(form.errors):
        case 0:
            await quart.flash("Ambiguous submission errors", category="warning")
        case 1:
            await quart.flash("There was 1 submission error", category="error")
        case _ as n:
            await quart.flash(f"There were {n} submission errors", category="error")
    return await shared.distribution.record_form_page(fpv, staging=True)
