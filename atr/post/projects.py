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

import quart

import atr.blueprints.post as post
import atr.get as get
import atr.shared as shared
import atr.storage as storage
import atr.util as util
import atr.web as web


@post.committer("/project/add/<committee_name>")
async def add_project(session: web.Committer, committee_name: str) -> web.WerkzeugResponse | str:
    return await shared.projects.add_project(session, committee_name)


@post.committer("/project/delete")
async def delete(session: web.Committer) -> web.WerkzeugResponse:
    """Delete a project created by the user."""
    # TODO: This is not truly empty, so make a form object for this
    await util.validate_empty_form()
    form_data = await quart.request.form
    project_name = form_data.get("project_name")
    if not project_name:
        return await session.redirect(get.projects.projects, error="Missing project name for deletion.")

    async with storage.write(session) as write:
        wacm = await write.as_project_committee_member(project_name)
        try:
            await wacm.project.delete(project_name)
        except storage.AccessError as e:
            # TODO: Redirect to committees
            return await session.redirect(get.projects.projects, error=f"Error deleting project: {e}")

    # TODO: Redirect to committees
    return await session.redirect(get.projects.projects, success=f"Project '{project_name}' deleted successfully.")


@post.committer("/projects/<name>")
async def view(session: web.Committer, name: str) -> web.WerkzeugResponse | str:
    return await shared.projects.view(session, name)
