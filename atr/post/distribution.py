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

import atr.blueprints.post as post
import atr.db as db
import atr.get as get
import atr.models.distribution as distribution
import atr.shared.distribution as shared
import atr.storage as storage
import atr.web as web


@post.committer("/distribution/delete/<project>/<version>")
@post.form(shared.DeleteForm)
async def delete(
    session: web.Committer, form: shared.DeleteForm, project: str, version: str
) -> web.WerkzeugResponse:
    dd = distribution.DeleteData.model_validate(form.model_dump())
    
    # Validate the submitted data, and obtain the committee for its name
    async with db.session() as data:
        release = await data.release(name=dd.release_name).demand(
            RuntimeError(f"Release {dd.release_name} not found")
        )
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
@post.form(shared.DistributeForm)
async def record_post(
    session: web.Committer, form: shared.DistributeForm, project: str, version: str
) -> str:
    # Pydantic validation happens automatically in @post.form
    return await shared.record_form_process_page_new(form, project, version, staging=False)


@post.committer("/distribution/stage/<project>/<version>")
@post.form(shared.DistributeForm)
async def stage_post(
    session: web.Committer, form: shared.DistributeForm, project: str, version: str
) -> str:
    # Pydantic validation happens automatically in @post.form
    return await shared.record_form_process_page_new(form, project, version, staging=True)
