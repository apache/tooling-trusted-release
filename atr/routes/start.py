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

import datetime

import asfquart.base as base
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.forms as forms
import atr.models.sql as sql
import atr.revision as revision
import atr.routes as routes
import atr.routes.compose as compose
import atr.template as template
import atr.util as util


class StartReleaseForm(forms.Typed):
    project_name = wtforms.HiddenField()
    version_name = wtforms.StringField(
        "Version",
        validators=[
            wtforms.validators.InputRequired("Version is required"),
            wtforms.validators.Length(min=1, max=100),
        ],
        render_kw={"placeholder": "Examples: 1.2.3+rc1 or 2.5"},
        description="Enter the version string for this new release.",
    )
    submit = wtforms.SubmitField("Start new release")


async def create_release_draft(project_name: str, version: str, asf_uid: str) -> tuple[sql.Release, sql.Project]:
    """Creates the initial release draft record and revision directory."""
    # Get the project from the project name
    async with db.session() as data:
        async with data.begin():
            project = await data.project(name=project_name, status=sql.ProjectStatus.ACTIVE, _committee=True).get()
            if not project:
                raise routes.FlashError(f"Project {project_name} not found")

            # TODO: Temporarily allow committers to start drafts
            if project.committee is None or (
                asf_uid not in project.committee.committee_members and asf_uid not in project.committee.committers
            ):
                raise base.ASFQuartException(
                    f"You must be a member or committer for the {project.display_name}"
                    " committee to start a release draft.",
                    errorcode=403,
                )

    # TODO: Consider using Release.revision instead of ./latest
    async with db.session() as data:
        async with data.begin():
            # Check whether the release already exists
            if release := await data.release(project_name=project.name, version=version).get():
                if release.phase == sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
                    raise routes.FlashError(f"A draft for {project_name} {version} already exists.")
                else:
                    raise routes.FlashError(
                        f"A release ({release.phase.value}) for {project_name} {version} already exists."
                    )

            # Validate the version name
            # TODO: We should check that it's bigger than the current version
            if version_name_error := util.version_name_error(version):
                raise routes.FlashError(f'Invalid version name "{version}": {version_name_error}')

            release = sql.Release(
                phase=sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
                project_name=project.name,
                project=project,
                version=version,
                created=datetime.datetime.now(datetime.UTC),
            )
            data.add(release)

        await data.refresh(release)

    description = "Creation of empty release candidate draft through web interface"
    async with revision.create_and_manage(project_name, version, asf_uid, description=description) as _creating:
        pass
    return release, project


@routes.committer("/start/<project_name>", methods=["GET", "POST"])
async def selected(session: routes.CommitterSession, project_name: str) -> response.Response | str:
    """Allow the user to start a new release draft, or handle its submission."""
    await session.check_access(project_name)

    async with db.session() as data:
        project = await data.project(name=project_name, status=sql.ProjectStatus.ACTIVE).demand(
            base.ASFQuartException(f"Project {project_name} not found", errorcode=404)
        )

    form = await StartReleaseForm.create_form(data=await quart.request.form if quart.request.method == "POST" else None)
    if (quart.request.method == "GET") or (not form.project_name.data):
        form.project_name.data = project_name

    if (quart.request.method == "POST") and (await form.validate_on_submit()):
        try:
            # TODO: Move the helper somewhere else
            # We already have the project, so we only need to get [0]
            new_release = (
                await create_release_draft(
                    project_name=str(form.project_name.data), version=str(form.version_name.data), asf_uid=session.uid
                )
            )[0]
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

    # Render the template for GET requests or POST requests with validation errors
    return await template.render("start-selected.html", project=project, form=form, routes=routes)
