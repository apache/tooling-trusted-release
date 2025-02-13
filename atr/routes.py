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

"routes.py"

from typing import List

from asfquart import APP
from asfquart.auth import Requirements as R, require
from asfquart.base import ASFQuartException
from asfquart.session import read as session_read
from quart import current_app, render_template, request
from sqlmodel import Session, select
from sqlalchemy.exc import IntegrityError

from .models import PMC

if APP is ...:
    raise ValueError("APP is not set")


@APP.route("/add-release-candidate", methods=["GET", "POST"])
@require(R.committer)
async def add_release_candidate() -> str:
    "Add a release candidate to the database."
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    # For POST requests, handle the file upload
    if request.method == "POST":
        # We'll implement the actual file handling later
        # For now just return a message about what we would do
        form = await request.form
        files = await request.files

        project_name = form.get("project_name")
        if not project_name:
            raise ASFQuartException("Project name is required", errorcode=400)

        # Verify user is a PMC member of the project
        if project_name not in session.committees:
            raise ASFQuartException(
                f"You must be a PMC member of {project_name} to submit a release candidate", errorcode=403
            )

        release_file = files.get("release_file")
        if not release_file:
            raise ASFQuartException("Release file is required", errorcode=400)

        # TODO: Implement actual file handling
        return f"Would process release candidate for {project_name} from file {release_file.filename}"

    # For GET requests, show the form
    return await render_template(
        "add-release-candidate.html",
        asf_id=session.uid,
        pmc_memberships=session.committees,
        committer_projects=session.projects,
    )


@APP.route("/pmc/create/<project_name>")
async def pmc_create_arg(project_name: str) -> dict:
    "Create a new PMC with some sample data."
    pmc = PMC(
        project_name=project_name,
        pmc_members=["alice", "bob"],
        committers=["charlie", "dave"],
        release_managers=["alice"],
    )

    with Session(current_app.config["engine"]) as session:
        try:
            session.add(pmc)
            session.commit()
            session.refresh(pmc)
        except IntegrityError:
            raise ASFQuartException(
                f"PMC with name '{project_name}' already exists",
                errorcode=409,  # HTTP 409 Conflict
            )

        # Convert to dict for response
        return {
            "id": pmc.id,
            "project_name": pmc.project_name,
            "pmc_members": pmc.pmc_members,
            "committers": pmc.committers,
            "release_managers": pmc.release_managers,
        }


@APP.route("/pmc/list")
async def pmc_list() -> List[dict]:
    "List all PMCs in the database."
    with Session(current_app.config["engine"]) as session:
        statement = select(PMC)
        pmcs = session.exec(statement).all()

        return [
            {
                "id": pmc.id,
                "project_name": pmc.project_name,
                "pmc_members": pmc.pmc_members,
                "committers": pmc.committers,
                "release_managers": pmc.release_managers,
            }
            for pmc in pmcs
        ]


@APP.route("/pmc/<project_name>")
async def pmc_arg(project_name: str) -> dict:
    "Get a specific PMC by project name."
    with Session(current_app.config["engine"]) as session:
        statement = select(PMC).where(PMC.project_name == project_name)
        pmc = session.exec(statement).first()

        if not pmc:
            raise ASFQuartException("PMC not found", errorcode=404)

        return {
            "id": pmc.id,
            "project_name": pmc.project_name,
            "pmc_members": pmc.pmc_members,
            "committers": pmc.committers,
            "release_managers": pmc.release_managers,
        }


@APP.route("/")
async def root() -> str:
    "Main PMC directory page."
    with Session(current_app.config["engine"]) as session:
        # Get all PMCs and their latest releases
        statement = select(PMC)
        pmcs = session.exec(statement).all()
        return await render_template("root.html", pmcs=pmcs)
