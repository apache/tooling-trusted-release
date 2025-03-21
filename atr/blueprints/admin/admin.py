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

import collections
import logging
import pathlib
import statistics
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

import aiofiles.os
import asfquart.base as base
import asfquart.session as session
import httpx
import quart
import werkzeug.wrappers.response as response

import atr.blueprints.admin as admin
import atr.datasources.apache as apache
import atr.db as db
import atr.db.models as models
import atr.util as util

if TYPE_CHECKING:
    from atr.datasources.apache import LDAPProject

_LOGGER = logging.getLogger(__name__)


@admin.BLUEPRINT.route("/performance")
async def admin_performance() -> str:
    """Display performance statistics for all routes."""
    from asfquart import APP

    if APP is ...:
        raise base.ASFQuartException("APP is not set", errorcode=500)

    # Read and parse the performance log file
    log_path = pathlib.Path("route-performance.log")
    # # Show current working directory and its files
    # cwd = await asyncio.to_thread(Path.cwd)
    # await asyncio.to_thread(APP.logger.info, "Current working directory: %s", cwd)
    # iterable = await asyncio.to_thread(cwd.iterdir)
    # files = list(iterable)
    # await asyncio.to_thread(APP.logger.info, "Files in current directory: %s", files)
    if not await aiofiles.os.path.exists(log_path):
        await quart.flash("No performance data currently available", "error")
        return await quart.render_template("performance.html", stats=None)

    # Parse the log file and collect statistics
    stats = collections.defaultdict(list)
    async with aiofiles.open(log_path) as f:
        async for line in f:
            try:
                _, _, _, methods, path, func, _, sync_ms, async_ms, total_ms = line.strip().split(" ")
                stats[path].append(
                    {
                        "methods": methods,
                        "function": func,
                        "sync_ms": int(sync_ms),
                        "async_ms": int(async_ms),
                        "total_ms": int(total_ms),
                        "timestamp": line.split(" - ")[0],
                    }
                )
            except (ValueError, IndexError):
                APP.logger.error("Error parsing line: %s", line)
                continue

    # Calculate summary statistics for each route
    summary = {}
    for path, timings in stats.items():
        total_times = [int(str(t["total_ms"])) for t in timings]
        sync_times = [int(str(t["sync_ms"])) for t in timings]
        async_times = [int(str(t["async_ms"])) for t in timings]

        summary[path] = {
            "count": len(timings),
            "methods": timings[0]["methods"],
            "function": timings[0]["function"],
            "total": {
                "mean": statistics.mean(total_times),
                "median": statistics.median(total_times),
                "min": min(total_times),
                "max": max(total_times),
                "stdev": statistics.stdev(total_times) if len(total_times) > 1 else 0,
            },
            "sync": {
                "mean": statistics.mean(sync_times),
                "median": statistics.median(sync_times),
                "min": min(sync_times),
                "max": max(sync_times),
            },
            "async": {
                "mean": statistics.mean(async_times),
                "median": statistics.median(async_times),
                "min": min(async_times),
                "max": max(async_times),
            },
            "last_timestamp": timings[-1]["timestamp"],
        }

    # Sort routes by average total time, descending
    def one_total_mean(x: tuple[str, dict]) -> float:
        return x[1]["total"]["mean"]

    sorted_summary = dict(sorted(summary.items(), key=one_total_mean, reverse=True))
    return await quart.render_template("performance.html", stats=sorted_summary)


@admin.BLUEPRINT.route("/data")
@admin.BLUEPRINT.route("/data/<model>")
async def admin_data(model: str = "Committee") -> str:
    """Browse all records in the database."""
    async with db.session() as data:
        # Map of model names to their classes
        # TODO: Add distribution channel, key link, and any others
        model_methods: dict[str, Callable[[], db.Query[Any]]] = {
            "Committee": data.committee,
            "Package": data.package,
            "Project": data.project,
            "PublicSigningKey": data.public_signing_key,
            "Release": data.release,
            "SSHKey": data.ssh_key,
            "Task": data.task,
            "VotePolicy": data.vote_policy,
        }

        if model not in model_methods:
            raise base.ASFQuartException(f"Model type '{model}' not found", 404)

        # Get all records for the selected model
        records = await model_methods[model]().all()

        # Convert records to dictionaries for JSON serialization
        records_dict = []
        for record in records:
            if hasattr(record, "dict"):
                record_dict = record.dict()
            else:
                # Fallback for models without dict() method
                record_dict = {
                    "id": getattr(record, "id", None),
                    "name": getattr(record, "name", None),
                }
                for key in record.__dict__:
                    if not key.startswith("_"):
                        record_dict[key] = getattr(record, key)
            records_dict.append(record_dict)

        return await quart.render_template(
            "data-browser.html", models=list(model_methods.keys()), model=model, records=records_dict
        )


@admin.BLUEPRINT.route("/projects/update", methods=["GET", "POST"])
async def admin_projects_update() -> str | response.Response | tuple[Mapping[str, Any], int]:
    """Update projects from remote data."""
    if quart.request.method == "POST":
        try:
            added_count, updated_count = await _update_committees()
            return {
                "message": f"Successfully added {added_count} and updated {updated_count} committees and projects "
                f"(PMCs and PPMCs) with membership data",
                "category": "success",
            }, 200
        except httpx.RequestError as e:
            return {
                "message": f"Failed to fetch data: {e!s}",
                "category": "error",
            }, 200
        except Exception as e:
            return {
                "message": f"Failed to update projects: {e!s}",
                "category": "error",
            }, 200

    # For GET requests, show the update form
    return await quart.render_template("update-committees.html")


async def _update_committees() -> tuple[int, int]:  # noqa: C901
    ldap_projects = await apache.get_ldap_projects_data()
    projects = await apache.get_projects_data()
    podlings_data = await apache.get_current_podlings_data()
    committees = await apache.get_active_committee_data()

    ldap_projects_by_name: Mapping[str, LDAPProject] = {p.name: p for p in ldap_projects.projects}
    committees_by_name: Mapping[str, apache.Committee] = {c.name: c for c in committees.committees}

    added_count = 0
    updated_count = 0

    async with db.session() as data:
        async with data.begin():
            # First create PMC committees
            for project in ldap_projects.projects:
                name = project.name
                # Skip non-PMC committees
                if project.pmc is not True:
                    continue

                # Get or create PMC
                committee = await data.committee(name=name).get()
                if not committee:
                    committee = models.Committee(name=name)
                    data.add(committee)
                    added_count += 1
                else:
                    updated_count += 1

                committee.committee_members = project.owners
                committee.committers = project.members
                # We create PMCs for now
                committee.is_podling = False
                committee_info = committees_by_name.get(name)
                if committee_info:
                    committee.full_name = committee_info.display_name

                updated_count += 1

            # Then add PPMCs and their associated project (podlings)
            for podling_name, podling_data in podlings_data:
                # Get or create PPMC
                ppmc = await data.committee(name=podling_name).get()
                if not ppmc:
                    ppmc = models.Committee(name=podling_name, is_podling=True)
                    data.add(ppmc)
                    added_count += 1
                else:
                    updated_count += 1

                # We create a PPMC
                ppmc.is_podling = True
                ppmc.full_name = podling_data.name.removesuffix("(Incubating)").removeprefix("Apache").strip()
                podling_project = ldap_projects_by_name.get(podling_name)
                if podling_project is not None:
                    ppmc.committee_members = podling_project.owners
                    ppmc.committers = podling_project.members
                else:
                    _LOGGER.warning(f"could not find ldap data for podling {podling_name}")

                podling = await data.project(name=podling_name).get()
                if not podling:
                    # create the associated podling project
                    podling = models.Project(
                        name=podling_name, full_name=podling_data.name, committee=ppmc, is_podling=True
                    )
                    data.add(podling)
                    added_count += 1
                else:
                    updated_count += 1

                podling.full_name = podling_data.name
                podling.committee = ppmc
                podling.is_podling = True

            # Add projects and associated them to the right PMC
            for project_name, project_status in projects.items():
                # FIXME: this is a quick workaround for inconsistent data wrt webservices PMC / projects
                #        the PMC seems to be identified by the key ws, but the associated projects use webservices
                if project_name.startswith("webservices-"):
                    project_name = project_name.replace("webservices-", "ws-")
                    project_status.pmc = "ws"

                pmc = await data.committee(name=project_status.pmc).get()
                if not pmc:
                    _LOGGER.warning(f"could not find PMC for project {project_name}: {project_status.pmc}")
                    continue

                project_model = await data.project(name=project_name).get()
                if not project_model:
                    project_model = models.Project(name=project_name, committee=pmc, is_podling=pmc.is_podling)
                    data.add(project_model)
                    added_count += 1
                else:
                    updated_count += 1

                project_model.full_name = project_status.name
                project_model.category = project_status.category
                project_model.description = project_status.description
                project_model.programming_languages = project_status.programming_language

                # TODO: find a better way to declare a project retired
                #       right now we assume that a project is retired if its assigned to the attic PMC
                #       maybe make that information configurable
                project_model.is_retired = pmc.name == "attic"

            # Tooling is not a committee
            # We add a special entry for Tooling, pretending to be a PMC, for debugging and testing
            tooling_committee = await data.committee(name="tooling").get()
            if not tooling_committee:
                tooling_committee = models.Committee(name="tooling")
                data.add(tooling_committee)
                tooling_project = models.Project(
                    name="tooling", full_name="Apache Tooling", committee=tooling_committee
                )
                data.add(tooling_project)
                added_count += 1
            else:
                updated_count += 1

            # Update Tooling PMC data
            # Could put this in the "if not tooling_committee" block, perhaps
            tooling_committee.committee_members = ["wave", "tn", "sbp"]
            tooling_committee.committers = ["wave", "tn", "sbp"]
            tooling_committee.release_managers = ["wave"]
            tooling_committee.is_podling = False

    return added_count, updated_count


@admin.BLUEPRINT.route("/tasks")
async def admin_tasks() -> str:
    return await quart.render_template("tasks.html")


@admin.BLUEPRINT.route("/keys/delete-all")
async def admin_keys_delete_all() -> str:
    """Debug endpoint to delete all of a user's keys."""
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)
    uid = util.unwrap(web_session.uid)

    async with db.session() as data:
        async with data.begin():
            # Get all keys for the user
            # TODO: Use session.apache_uid instead of session.uid?
            keys = await data.public_signing_key(apache_uid=uid).all()
            count = len(keys)

            # Delete all keys
            for key in keys:
                await data.delete(key)

        return f"Deleted {count} keys"
