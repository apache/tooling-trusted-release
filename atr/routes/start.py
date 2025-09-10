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
import werkzeug.wrappers.response as response

import atr.db as db
import atr.db.interaction as interaction
import atr.forms as forms
import atr.models.sql as sql
import atr.routes as routes
import atr.routes.compose as compose
import atr.storage as storage
import atr.template as template


class StartReleaseForm(forms.Typed):
    project_name = forms.hidden()
    version_name = forms.string(
        "Version",
        placeholder="Examples: 1.2.3+rc1 or 2.5",
        description="Enter the version string for this new release.",
    )
    submit = forms.submit("Start new release")


@routes.committer("/start/<project_name>", methods=["GET", "POST"])
async def selected(session: routes.CommitterSession, project_name: str) -> response.Response | str:
    """Allow the user to start a new release draft, or handle its submission."""
    await session.check_access(project_name)

    async with db.session() as data:
        project = await data.project(name=project_name, status=sql.ProjectStatus.ACTIVE).demand(
            base.ASFQuartException(f"Project {project_name} not found", errorcode=404)
        )

    form = await StartReleaseForm.create_form(
        data=await quart.request.form if (quart.request.method == "POST") else None
    )
    if (quart.request.method == "GET") or (not form.project_name.data):
        form.project_name.data = project_name

    if (quart.request.method == "POST") and (await form.validate_on_submit()):
        try:
            project_name = str(form.project_name.data)
            version = str(form.version_name.data)
            # We already have the project, so we only need to get the new release
            async with storage.write(session.uid) as write:
                wacp = await write.as_project_committee_participant(project_name)
                new_release, _project = await wacp.release.start(project_name, version)
            # Redirect to the new draft's overview page on success
            return await session.redirect(
                compose.selected,
                project_name=project.name,
                version_name=new_release.version,
                success="Release candidate draft created successfully",
            )
        except (routes.FlashError, base.ASFQuartException) as e:
            # Flash the error and let the code fall through to render the template below
            await quart.flash(str(e), "error")

    # Get all releases for the project
    releases = await interaction.all_releases(project)

    # Render the template for GET requests or POST requests with validation errors
    return await template.render("start-selected.html", project=project, form=form, routes=routes, releases=releases)
