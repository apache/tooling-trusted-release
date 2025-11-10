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

import asfquart.base as base
import quart

import atr.blueprints.post as post
import atr.get as get
import atr.shared as shared
import atr.storage as storage
import atr.web as web


@post.committer("/start/<project_name>")
@post.form(shared.start.StartReleaseForm)
async def selected(
    session: web.Committer, start_release_form: shared.start.StartReleaseForm, project_name: str
) -> web.WerkzeugResponse:
    await session.check_access(project_name)

    try:
        async with storage.write(session) as write:
            wacp = await write.as_project_committee_participant(project_name)
            new_release, _project = await wacp.release.start(
                project_name,
                start_release_form.version_name,
            )

        return await session.redirect(
            get.compose.selected,
            project_name=project_name,
            version_name=new_release.version,
            success="Release candidate draft created successfully",
        )
    except (web.FlashError, base.ASFQuartException) as e:
        await quart.flash(str(e), "error")
        return await session.redirect(get.start.selected, project_name=project_name)
