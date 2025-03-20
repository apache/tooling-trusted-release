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

"""candidate.py"""

import datetime

import quart
import werkzeug.wrappers.response as response
import wtforms

import asfquart
import asfquart.auth as auth
import asfquart.base as base
import asfquart.session as session
import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.util as util

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")


class ReleaseAddForm(util.QuartFormTyped):
    committee_name = wtforms.StringField(
        "Committee", validators=[wtforms.validators.InputRequired("Committee name is required")]
    )
    version = wtforms.StringField("Version", validators=[wtforms.validators.InputRequired("Version is required")])
    project_name = wtforms.StringField(
        "Project name", validators=[wtforms.validators.InputRequired("Project name is required")]
    )
    submit = wtforms.SubmitField("Create release candidate")


def format_artifact_name(project_name: str, version: str, is_podling: bool = False) -> str:
    """Format an artifact name according to Apache naming conventions.

    For regular projects: apache-${project}-${version}
    For podlings: apache-${project}-incubating-${version}
    """
    # TODO: Format this better based on committee and project
    # Must depend on whether project is a subproject or not
    if is_podling:
        return f"apache-{project_name}-incubating-{version}"
    return f"apache-{project_name}-{version}"


# Release functions


async def release_add_post(session: session.ClientSession, request: quart.Request) -> str | response.Response:
    """Handle POST request for creating a new release."""

    def not_none(value: str | None) -> str:
        if value is None:
            raise ValueError("This field is required")
        return value

    form = await ReleaseAddForm.create_form(data=await request.form)

    if not await form.validate():
        # Get Committee objects for all committees and projects the user is a member of
        async with db.session() as data:
            committee_and_project_list = session.committees + session.projects
            user_committees = await data.committee(name_in=committee_and_project_list).all()

        # Return the form with validation errors
        return await quart.render_template(
            "candidate-create.html",
            asf_id=session.uid,
            user_committees=user_committees,
            form=form,
        )

    committee_name = str(form.committee_name.data)
    version = not_none(form.version.data)
    project_name = not_none(form.project_name.data)

    # TODO: Forbid creating a release with an existing project and version
    # Create the release record in the database
    async with db.session() as data:
        async with data.begin():
            committee = await data.committee(name=committee_name).get()
            if not committee:
                asfquart.APP.logger.error(f"Committee not found for project {committee_name}")
                raise base.ASFQuartException("Committee not found", errorcode=404)

            # Verify user is a PMC member or committer of the project
            # We use committee.name, so this must come within the transaction
            if committee.name not in (session.committees + session.projects):
                raise base.ASFQuartException(
                    f"You must be a PMC member or committer of {committee.display_name} to submit a release candidate",
                    errorcode=403,
                )

            release_name = f"{project_name}-{version}"
            project = await data.project(name=project_name).get()
            if not project:
                # Create a new project record
                project = models.Project(
                    name=project_name,
                    committee_id=committee.id,
                )
                data.add(project)
                # Must flush to get the project ID
                await data.flush()

            # Create release record with project
            release = models.Release(
                name=release_name,
                stage=models.ReleaseStage.CANDIDATE,
                phase=models.ReleasePhase.RELEASE_CANDIDATE,
                project_id=project.id,
                project=project,
                version=version,
                created=datetime.datetime.now(datetime.UTC),
            )
            data.add(release)

    # Redirect to the add package page with the storage token
    return quart.redirect(quart.url_for("root_package_add", name=release_name))


# Root functions


@routes.app_route("/candidate/create", methods=["GET", "POST"])
@auth.require(auth.Requirements.committer)
async def root_candidate_create() -> response.Response | str:
    """Create a new release in the database."""
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    # For POST requests, handle the release creation
    if quart.request.method == "POST":
        return await release_add_post(web_session, quart.request)

    # Get PMC objects for all projects the user is a member of
    async with db.session() as data:
        project_list = web_session.committees + web_session.projects
        user_committees = await data.committee(name_in=project_list).all()

    # For GET requests, show the form
    form = await ReleaseAddForm.create_form()
    return await quart.render_template(
        "candidate-create.html",
        asf_id=web_session.uid,
        user_committees=user_committees,
        form=form,
    )


@routes.app_route("/candidate/review")
@auth.require(auth.Requirements.committer)
async def root_candidate_review() -> str:
    """Show all release candidates to which the user has access."""
    # time.sleep(0.37)
    # await asyncio.sleep(0.73)
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    async with db.session() as data:
        # Get all releases where the user is a PMC member or committer
        # TODO: We don't actually record who uploaded the release candidate
        # We should probably add that information!
        # TODO: This duplicates code in root_package_add
        releases = await data.release(
            stage=models.ReleaseStage.CANDIDATE,
            _committee=True,
            _packages_tasks=True,
        ).all()

        # Filter to only show releases for PMCs or PPMCs where the user is a member or committer
        user_releases = []
        for r in releases:
            if r.committee is None:
                continue
            # For PPMCs the "members" are stored in the committers field
            if (web_session.uid in r.committee.committee_members) or (web_session.uid in r.committee.committers):
                user_releases.append(r)

        # time.sleep(0.37)
        # await asyncio.sleep(0.73)
        return await quart.render_template(
            "candidate-review.html",
            releases=user_releases,
            format_file_size=routes.format_file_size,
            format_artifact_name=format_artifact_name,
        )
