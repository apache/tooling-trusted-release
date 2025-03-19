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
import pathlib
import statistics
from collections.abc import Callable, Mapping
from typing import Any

import aiofiles.os
import httpx
import quart
import werkzeug.wrappers.response as response

import asfquart.base as base
import asfquart.session as session
import atr.blueprints.admin as admin
import atr.datasources.apache as apache
import atr.db as db
import atr.db.models as models


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
                    "storage_key": getattr(record, "storage_key", None),
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
            updated_count = await _update_committees()
            return {
                "message": f"Successfully updated {updated_count} projects (PMCs and PPMCs) with membership data",
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


async def _update_committees() -> int:
    ldap_projects = await apache.get_ldap_projects_data()
    projects = await apache.get_projects_data()
    podlings_data = await apache.get_current_podlings_data()
    groups_data = await apache.get_groups_data()

    updated_count = 0

    async with db.session() as data:
        async with data.begin():
            # First update PMCs
            for project in ldap_projects.projects:
                name = project.name
                # Skip non-PMC committees
                if project.pmc is None:
                    continue

                # Get or create PMC
                committee = await data.committee(name=name).get()
                if not committee:
                    committee = models.Committee(name=name)
                    data.add(committee)
                    committee_core_project = models.Project(name=name, committee=committee)

                    project_status = projects.get(name)
                    if project_status is not None:
                        committee_core_project.full_name = project_status.name

                    data.add(committee_core_project)

                committee.committee_members = project.owners
                committee.committers = project.members
                # Ensure this is set for PMCs
                committee.is_podling = False

                # For release managers, use PMC members for now
                # TODO: Consider a more sophisticated way to determine release managers
                #       from my POV, the list of release managers should be the list of people
                #       that have actually cut a release for that project
                committee.release_managers = committee.committee_members

                updated_count += 1

            # Then add PPMCs (podlings)
            for podling_name, podling_data in podlings_data:
                # Get or create PPMC
                podling = await data.committee(name=podling_name).get()
                if not podling:
                    podling = models.Committee(name=podling_name, is_podling=True)
                    data.add(podling)
                    podling_core_project = models.Project(name=podling_name, committee=podling)
                    data.add(podling_core_project)

                # Update PPMC data from groups.json
                podling.is_podling = True
                pmc_members = groups_data.get(f"{podling_name}-pmc")
                committers = groups_data.get(podling_name)
                podling.committee_members = pmc_members if pmc_members is not None else []
                podling.committers = committers if committers is not None else []
                # Use PPMC members as release managers
                podling.release_managers = podling.committee_members

                updated_count += 1

            # Add special entry for Tooling PMC
            # Not clear why, but it's not in the Whimsy data
            tooling_committee = await data.committee(name="tooling").get()
            if not tooling_committee:
                tooling_committee = models.Committee(name="tooling")
                data.add(tooling_committee)
                tooling_project = models.Project(name="tooling", committee=tooling_committee)
                data.add(tooling_project)
                updated_count += 1

            # Update Tooling PMC data
            # Could put this in the "if not tooling_committee" block, perhaps
            tooling_committee.committee_members = ["wave", "tn", "sbp"]
            tooling_committee.committers = ["wave", "tn", "sbp"]
            tooling_committee.release_managers = ["wave"]
            tooling_committee.is_podling = False

    return updated_count


@admin.BLUEPRINT.route("/tasks")
async def admin_tasks() -> str:
    return await quart.render_template("tasks.html")


@admin.BLUEPRINT.route("/keys/delete-all")
async def admin_keys_delete_all() -> str:
    """Debug endpoint to delete all of a user's keys."""
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    async with db.session() as data:
        async with data.begin():
            # Get all keys for the user
            # TODO: Use session.apache_uid instead of session.uid?
            keys = await data.public_signing_key(apache_uid=web_session.uid).all()
            count = len(keys)

            # Delete all keys
            for key in keys:
                await data.delete(key)

        return f"Deleted {count} keys"
