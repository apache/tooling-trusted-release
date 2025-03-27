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

import asfquart
import asfquart.base as base
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.db.service as service
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


async def release_add_post(session: routes.CommitterSession, request: quart.Request) -> str | response.Response:
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
                stage=models.ReleaseStage.RELEASE_CANDIDATE,
                phase=models.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
                project_id=project.id,
                project=project,
                version=version,
                created=datetime.datetime.now(datetime.UTC),
            )
            data.add(release)

    # Redirect to the add package page with the storage token
    return await session.redirect(vote, success="Release candidate created successfully")


# Root functions


@routes.committer("/candidate/create", methods=["GET", "POST"])
async def create(session: routes.CommitterSession) -> response.Response | str:
    """Create a new release in the database."""
    # For POST requests, handle the release creation
    if quart.request.method == "POST":
        return await release_add_post(session, quart.request)

    # Get PMC objects for all projects the user is a member of
    async with db.session() as data:
        project_list = session.committees + session.projects
        user_committees = await data.committee(name_in=project_list).all()

    # For GET requests, show the form
    form = await ReleaseAddForm.create_form()
    return await quart.render_template(
        "candidate-create.html",
        asf_id=session.uid,
        user_committees=user_committees,
        form=form,
    )


@routes.committer("/candidate/vote")
async def vote(session: routes.CommitterSession) -> str:
    """Show all release candidates to which the user has access."""
    async with db.session() as data:
        # Get all releases where the user is a PMC member or committer
        # TODO: We don't actually record who uploaded the release candidate
        # We should probably add that information!
        releases = await data.release(
            stage=models.ReleaseStage.RELEASE_CANDIDATE,
            phase=models.ReleasePhase.RELEASE_CANDIDATE_BEFORE_VOTE,
            _committee=True,
            _packages=True,
        ).all()

        # Filter to only show releases for PMCs or PPMCs where the user is a member or committer
        user_candidates = []
        for r in releases:
            if r.committee is None:
                continue
            # For PPMCs the "members" are stored in the committers field
            if (session.uid in r.committee.committee_members) or (session.uid in r.committee.committers):
                user_candidates.append(r)

        # time.sleep(0.37)
        # await asyncio.sleep(0.73)
        return await quart.render_template(
            "candidate-vote.html",
            candidates=user_candidates,
            format_file_size=routes.format_file_size,
            format_artifact_name=format_artifact_name,
        )


@routes.committer("/candidate/vote/<project_name>/<version>", methods=["GET", "POST"])
async def vote_project(session: routes.CommitterSession, project_name: str, version: str) -> response.Response | str:
    """Show the vote initiation form for a release."""
    release_name = f"{project_name}-{version}"
    release = await service.get_release_by_name(release_name)
    if release is None:
        return await session.redirect(vote, error=f"Release with key {release_name} not found")

    # If POST, process the form and create a vote_initiate task
    if quart.request.method == "POST":
        form = await routes.get_form(quart.request)
        # Extract form data
        mailing_list = form.get("mailing_list", "dev")
        vote_duration = form.get("vote_duration", "72")
        # These fields are just for testing, we'll do something better in the real UI
        gpg_key_id = form.get("gpg_key_id", "")
        commit_hash = form.get("commit_hash", "")
        if release.committee is None:
            raise base.ASFQuartException("Release has no associated committee", errorcode=400)

        # Prepare email recipient
        email_to = f"{mailing_list}@{release.committee.name}.apache.org"

        # Create a task for vote initiation
        task = models.Task(
            status=models.TaskStatus.QUEUED,
            task_type="vote_initiate",
            task_args=[
                release_name,
                email_to,
                vote_duration,
                gpg_key_id,
                commit_hash,
                session.uid,
            ],
        )
        async with db.create_async_db_session() as db_session:
            db_session.add(task)
            # Flush to get the task ID
            await db_session.flush()
            await db_session.commit()

        return await session.redirect(
            vote,
            success=f"Vote initiation task queued as task #{task.id}."
            f" You'll receive an email confirmation when complete.",
        )

    # For GET
    return await quart.render_template(
        "release-vote.html",
        release=release,
        email_preview=_generate_vote_email_preview(release),
    )


def _generate_vote_email_preview(release: models.Release) -> str:
    """Generate a preview of the vote email."""
    version = release.version

    # Get PMC details
    if release.committee is None:
        raise base.ASFQuartException("Release has no associated committee", errorcode=400)
    committee_name = release.committee.name
    committee_display = release.committee.display_name

    # Get project information
    project_name = release.project.name if release.project else "Unknown"

    # Create email subject
    subject = f"[VOTE] Release Apache {committee_display} {project_name} {version}"

    # Create email body
    body = f"""Hello {committee_name},

I'd like to call a vote on releasing the following artifacts as
Apache {committee_display} {project_name} {version}.

The release candidate can be found at:

https://apache.example.org/{committee_name}/{project_name}-{version}/

The release artifacts are signed with my GPG key, [KEY_ID].

The artifacts were built from commit:

[COMMIT_HASH]

Please review the release candidate and vote accordingly.

[ ] +1 Release this package
[ ] +0 Abstain
[ ] -1 Do not release this package (please provide specific comments)

This vote will remain open for at least 72 hours.

Thanks,
[YOUR_NAME]
"""
    return f"{subject}\n\n{body}"
