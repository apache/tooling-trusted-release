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
import json
import secrets

import httpx
from quart import current_app, flash, redirect, render_template, request, url_for
from sqlmodel import select
from werkzeug.wrappers.response import Response

from asfquart.base import ASFQuartException
from asfquart.session import read as session_read
from atr.apache import get_apache_project_data
from atr.db import get_session
from atr.db.models import (
    PMC,
    DistributionChannel,
    Package,
    PMCKeyLink,
    ProductLine,
    PublicSigningKey,
    Release,
    Task,
    TaskStatus,
    VotePolicy,
)
from atr.db.service import get_pmcs

from . import blueprint

_WHIMSY_COMMITTEE_URL = "https://whimsy.apache.org/public/committee-info.json"


@blueprint.route("/data")
@blueprint.route("/data/<model>")
async def secret_data(model: str = "PMC") -> str:
    """Browse all records in the database."""

    # Map of model names to their classes
    models = {
        "PMC": PMC,
        "Release": Release,
        "Package": Package,
        "VotePolicy": VotePolicy,
        "ProductLine": ProductLine,
        "DistributionChannel": DistributionChannel,
        "PublicSigningKey": PublicSigningKey,
        "PMCKeyLink": PMCKeyLink,
        "Task": Task,
    }

    if model not in models:
        raise ASFQuartException(f"Model type '{model}' not found", 404)

    async with get_session() as db_session:
        # Get all records for the selected model
        statement = select(models[model])
        records = (await db_session.execute(statement)).scalars().all()

        # Convert records to dictionaries for JSON serialization
        records_dict = []
        for record in records:
            if hasattr(record, "dict"):
                record_dict = record.dict()
            else:
                # Fallback for models without dict() method
                record_dict = {
                    "id": getattr(record, "id", None),
                    "storage_key": getattr(record, "storage_key", None),
                }
                for key in record.__dict__:
                    if not key.startswith("_"):
                        record_dict[key] = getattr(record, key)
            records_dict.append(record_dict)

        return await render_template(
            "secret/data-browser.html", models=list(models.keys()), model=model, records=records_dict
        )


@blueprint.route("/pmcs/update", methods=["GET", "POST"])
async def secret_pmcs_update() -> str | Response:
    """Update PMCs from remote, authoritative committee-info.json."""

    if request.method == "POST":
        # Fetch committee-info.json from Whimsy
        try:
            apache_projects = await get_apache_project_data()
        except (httpx.RequestError, json.JSONDecodeError) as e:
            await flash(f"Failed to fetch committee data: {e!s}", "error")
            return redirect(url_for("secret_blueprint.secret_pmcs_update"))

        updated_count = 0

        try:
            async with get_session() as db_session:
                async with db_session.begin():
                    for project in apache_projects.projects:
                        name = project.name
                        # Skip non-PMC committees
                        if not project.pmc:
                            continue

                        # Get or create PMC
                        statement = select(PMC).where(PMC.project_name == name)
                        pmc = (await db_session.execute(statement)).scalar_one_or_none()
                        if not pmc:
                            pmc = PMC(project_name=name)
                            db_session.add(pmc)

                        # Update PMC data
                        pmc.pmc_members = project.owners
                        pmc.committers = project.members

                        # Mark chairs as release managers
                        # TODO: Who else is a release manager? How do we know?
                        #       lets assume for now that all owners are also release managers
                        pmc.release_managers = project.owners

                        updated_count += 1

                    # Add special entry for Tooling PMC
                    # Not clear why, but it's not in the Whimsy data
                    statement = select(PMC).where(PMC.project_name == "tooling")
                    tooling_pmc = (await db_session.execute(statement)).scalar_one_or_none()
                    if not tooling_pmc:
                        tooling_pmc = PMC(project_name="tooling")
                        db_session.add(tooling_pmc)
                        updated_count += 1

                    # Update Tooling PMC data
                    # Could put this in the "if not tooling_pmc" block, perhaps
                    tooling_pmc.pmc_members = ["wave", "tn", "sbp"]
                    tooling_pmc.committers = ["wave", "tn", "sbp"]
                    tooling_pmc.release_managers = ["wave"]

            await flash(f"Successfully updated {updated_count} PMCs from Whimsy", "success")
        except Exception as e:
            await flash(f"Failed to update PMCs: {e!s}", "error")

        return redirect(url_for("secret_blueprint.secret_pmcs_update"))

    # For GET requests, show the update form
    return await render_template("secret/update-pmcs.html")


@blueprint.route("/debug/database")
async def secret_debug_database() -> str:
    """Debug information about the database."""
    pmcs = await get_pmcs()
    return f"Database using {current_app.config['DATA_MODELS_FILE']} has {len(pmcs)} PMCs"


@blueprint.route("/keys/delete-all")
async def secret_keys_delete_all() -> str:
    """Debug endpoint to delete all of a user's keys."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    async with get_session() as db_session:
        async with db_session.begin():
            # Get all keys for the user
            # TODO: Use session.apache_uid instead of session.uid?
            statement = select(PublicSigningKey).where(PublicSigningKey.apache_uid == session.uid)
            keys = (await db_session.execute(statement)).scalars().all()
            count = len(keys)

            # Delete all keys
            for key in keys:
                await db_session.delete(key)

        return f"Deleted {count} keys"


@blueprint.route("/tasks/add-random", methods=["GET", "POST"])
async def secret_tasks_add_random() -> str | Response:
    """Add a random task to the queue for testing."""
    if request.method == "POST":
        async with get_session() as db_session:
            async with db_session.begin():
                # Create a random task
                task = Task(
                    id=None,
                    task_type="example",
                    task_args=json.dumps(
                        {
                            "random_number": secrets.randbelow(100),
                            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                        }
                    ),
                    status=TaskStatus.QUEUED,
                )
                db_session.add(task)
                # Flush to get the task ID
                await db_session.flush()
                await flash(f"Added random task (ID: {task.id})", "success")

        return redirect(url_for("secret_blueprint.secret_tasks_add_random"))

    return await render_template("secret/tasks-add-random.html")
