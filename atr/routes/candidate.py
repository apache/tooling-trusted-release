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
import secrets
from typing import cast

from quart import Request, redirect, render_template, request, url_for
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlmodel import select
from werkzeug.wrappers.response import Response

from asfquart import APP
from asfquart.auth import Requirements, require
from asfquart.base import ASFQuartException
from asfquart.session import ClientSession
from asfquart.session import read as session_read
from atr.db import create_async_db_session
from atr.db.models import (
    PMC,
    Package,
    ProductLine,
    Release,
    ReleasePhase,
    ReleaseStage,
    Task,
)
from atr.routes import app_route, format_file_size, get_form

if APP is ...:
    raise RuntimeError("APP is not set")


def format_artifact_name(project_name: str, product_name: str, version: str, is_podling: bool = False) -> str:
    """Format an artifact name according to Apache naming conventions.

    For regular projects: apache-${project}-${product}-${version}
    For podlings: apache-${project}-incubating-${product}-${version}
    """
    if is_podling:
        return f"apache-{project_name}-incubating-{product_name}-{version}"
    return f"apache-{project_name}-{product_name}-{version}"


# Release functions


async def release_add_post(session: ClientSession, request: Request) -> Response:
    """Handle POST request for creating a new release."""
    form = await get_form(request)

    project_name = form.get("project_name")
    if not project_name:
        raise ASFQuartException("Project name is required", errorcode=400)

    product_name = form.get("product_name")
    if not product_name:
        raise ASFQuartException("Product name is required", errorcode=400)

    version = form.get("version")
    if not version:
        raise ASFQuartException("Version is required", errorcode=400)

    # TODO: Forbid creating a release with an existing project, product, and version
    # Create the release record in the database
    async with create_async_db_session() as db_session:
        async with db_session.begin():
            statement = select(PMC).where(PMC.project_name == project_name)
            pmc = (await db_session.execute(statement)).scalar_one_or_none()
            if not pmc:
                APP.logger.error(f"PMC not found for project {project_name}")
                APP.logger.debug(f"Available committees: {session.committees}")
                APP.logger.debug(f"Available projects: {session.projects}")
                raise ASFQuartException("PMC not found", errorcode=404)

            # Verify user is a PMC member or committer of the project
            # We use pmc.display_name, so this must come within the transaction
            if project_name not in session.committees and project_name not in session.projects:
                raise ASFQuartException(
                    f"You must be a PMC member or committer of {pmc.display_name} to submit a release candidate",
                    errorcode=403,
                )

            # Generate a 128-bit random token for the release storage key
            # TODO: Perhaps we should call this the release_key instead
            storage_key = secrets.token_hex(16)

            # Create or get existing product line
            statement = select(ProductLine).where(
                ProductLine.pmc_id == pmc.id, ProductLine.product_name == product_name
            )
            product_line = (await db_session.execute(statement)).scalar_one_or_none()

            if not product_line:
                # Create new product line if it doesn't exist
                product_line = ProductLine(pmc_id=pmc.id, product_name=product_name, latest_version=version)
                db_session.add(product_line)
                # Flush to get the product_line.id
                await db_session.flush()

            # Create release record with product line
            release = Release(
                storage_key=storage_key,
                stage=ReleaseStage.CANDIDATE,
                phase=ReleasePhase.RELEASE_CANDIDATE,
                pmc_id=pmc.id,
                product_line_id=product_line.id,
                version=version,
                created=datetime.datetime.now(datetime.UTC),
            )
            db_session.add(release)

    # Redirect to the add package page with the storage token
    return redirect(url_for("root_package_add", storage_key=storage_key))


# Root functions


@app_route("/candidate/create", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_candidate_create() -> Response | str:
    """Create a new release in the database."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    # For POST requests, handle the release creation
    if request.method == "POST":
        return await release_add_post(session, request)

    # Get PMC objects for all projects the user is a member of
    async with create_async_db_session() as db_session:
        from sqlalchemy.sql.expression import ColumnElement

        project_list = session.committees + session.projects
        project_name: ColumnElement[str] = cast(ColumnElement[str], PMC.project_name)
        statement = select(PMC).where(project_name.in_(project_list))
        user_pmcs = (await db_session.execute(statement)).scalars().all()

    # For GET requests, show the form
    return await render_template(
        "candidate-create.html",
        asf_id=session.uid,
        user_pmcs=user_pmcs,
    )


@app_route("/candidate/review")
@require(Requirements.committer)
async def root_candidate_review() -> str:
    """Show all release candidates to which the user has access."""
    # time.sleep(0.37)
    # await asyncio.sleep(0.73)
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    async with create_async_db_session() as db_session:
        # Get all releases where the user is a PMC member or committer
        # TODO: We don't actually record who uploaded the release candidate
        # We should probably add that information!
        # TODO: This duplicates code in root_package_add
        release_pmc = selectinload(cast(InstrumentedAttribute[PMC], Release.pmc))
        release_packages = selectinload(cast(InstrumentedAttribute[list[Package]], Release.packages))
        package_tasks = release_packages.selectinload(cast(InstrumentedAttribute[list[Task]], Package.tasks))
        release_product_line = selectinload(cast(InstrumentedAttribute[ProductLine], Release.product_line))
        statement = (
            select(Release)
            .options(release_pmc, release_packages, package_tasks, release_product_line)
            .join(PMC)
            .where(Release.stage == ReleaseStage.CANDIDATE)
        )
        releases = (await db_session.execute(statement)).scalars().all()

        # Filter to only show releases for PMCs or PPMCs where the user is a member or committer
        user_releases = []
        for r in releases:
            if r.pmc is None:
                continue
            # For PPMCs the "members" are stored in the committers field
            if session.uid in r.pmc.pmc_members or session.uid in r.pmc.committers:
                user_releases.append(r)

        # time.sleep(0.37)
        # await asyncio.sleep(0.73)
        return await render_template(
            "candidate-review.html",
            releases=user_releases,
            format_file_size=format_file_size,
            format_artifact_name=format_artifact_name,
        )
