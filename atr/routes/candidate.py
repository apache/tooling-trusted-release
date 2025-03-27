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

import asfquart
import asfquart.base as base
import quart
import werkzeug.wrappers.response as response

import atr.db as db
import atr.db.models as models
import atr.db.service as service
import atr.routes as routes

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")


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


@routes.committer("/candidate/delete", methods=["POST"])
async def delete(session: routes.CommitterSession) -> response.Response:
    """Delete a release candidate."""
    return await session.redirect(vote, error="Not yet implemented")


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
