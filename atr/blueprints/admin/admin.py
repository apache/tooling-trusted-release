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
import os
import pathlib
import statistics
from collections.abc import Callable, Mapping
from typing import Any, Final

import aiofiles.os
import aioshutil
import asfquart
import asfquart.base as base
import asfquart.session as session
import httpx
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.blueprints.admin as admin
import atr.datasources.apache as apache
import atr.db as db
import atr.db.interaction as interaction
import atr.db.models as models
import atr.util as util

_LOGGER: Final = logging.getLogger(__name__)


class DeleteReleaseForm(util.QuartFormTyped):
    """Form for deleting releases."""

    confirm_delete = wtforms.StringField(
        "Confirmation",
        validators=[
            wtforms.validators.InputRequired("Confirmation is required"),
            wtforms.validators.Regexp("^DELETE$", message="Please type DELETE to confirm"),
        ],
    )
    submit = wtforms.SubmitField("Delete selected releases permanently")


@admin.BLUEPRINT.route("/data")
@admin.BLUEPRINT.route("/data/<model>")
async def admin_data(model: str = "Committee") -> str:
    """Browse all records in the database."""
    async with db.session() as data:
        # Map of model names to their classes
        # TODO: Add distribution channel, key link, and any others
        model_methods: dict[str, Callable[[], db.Query[Any]]] = {
            "CheckResult": data.check_result,
            "Committee": data.committee,
            "Project": data.project,
            "PublicSigningKey": data.public_signing_key,
            "Release": data.release,
            "ReleasePolicy": data.release_policy,
            "SSHKey": data.ssh_key,
            "Task": data.task,
            "TextValue": data.text_value,
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
                record_dict = {}
                # record_dict = {
                #     "id": getattr(record, "id", None),
                #     "name": getattr(record, "name", None),
                # }
                for key in record.__dict__:
                    if not key.startswith("_"):
                        record_dict[key] = getattr(record, key)
            records_dict.append(record_dict)

        return await quart.render_template(
            "data-browser.html", models=list(model_methods.keys()), model=model, records=records_dict
        )


@admin.BLUEPRINT.route("/delete-release", methods=["GET", "POST"])
async def admin_delete_release() -> str | response.Response:
    """Page to delete selected releases and their associated data and files."""
    form = await DeleteReleaseForm.create_form()

    if quart.request.method == "POST":
        if await form.validate_on_submit():
            form_data = await quart.request.form
            releases_to_delete = form_data.getlist("releases_to_delete")

            if not releases_to_delete:
                await quart.flash("No releases selected for deletion.", "warning")
                return quart.redirect(quart.url_for("admin.admin_delete_release"))

            success_count = 0
            fail_count = 0
            error_messages = []

            for release_name in releases_to_delete:
                try:
                    await _delete_release_data(release_name)
                    success_count += 1
                except base.ASFQuartException as e:
                    _LOGGER.error("Error deleting release %s: %s", release_name, e)
                    fail_count += 1
                    error_messages.append(f"{release_name}: {e}")
                except Exception:
                    _LOGGER.exception("Unexpected error deleting release %s:", release_name)
                    fail_count += 1
                    error_messages.append(f"{release_name}: Unexpected error")

            if success_count > 0:
                await quart.flash(f"Successfully deleted {success_count} release(s).", "success")
            if fail_count > 0:
                errors_str = "\n".join(error_messages)
                await quart.flash(f"Failed to delete {fail_count} release(s):\n{errors_str}", "error")

            # Redirecting back to the deletion page will refresh the list of releases too
            return quart.redirect(quart.url_for("admin.admin_delete_release"))

        # It's unlikely that form validation failed due to spurious release names
        # Therefore we assume that the user forgot to type DELETE to confirm
        await quart.flash("Form validation failed. Please type DELETE to confirm.", "warning")
        # Fall through to the combined GET and failed form validation handling below

    # For GET request or failed form validation
    async with db.session() as data:
        releases = await data.release(_project=True).order_by(models.Release.name).all()
    return await quart.render_template("delete-release.html", form=form, releases=releases, stats=None)


@admin.BLUEPRINT.route("/env")
async def admin_env() -> quart.wrappers.response.Response:
    """Display the environment variables."""
    env_vars = []
    for key, value in os.environ.items():
        env_vars.append(f"{key}={value}")
    return quart.Response("\n".join(env_vars), mimetype="text/plain")


@admin.BLUEPRINT.route("/performance")
async def admin_performance() -> str:
    """Display performance statistics for all routes."""
    app = asfquart.APP

    if app is ...:
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
                app.logger.error("Error parsing line: %s", line)
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
    empty_form = await util.EmptyForm.create_form()
    return await quart.render_template("update-projects.html", empty_form=empty_form)


@admin.BLUEPRINT.route("/releases")
async def admin_releases() -> str:
    """Display a list of all releases across all stages and phases."""
    async with db.session() as data:
        releases = await data.release(_project=True, _committee=True).order_by(models.Release.name).all()
    return await quart.render_template("releases.html", releases=releases)


@admin.BLUEPRINT.route("/tasks")
async def admin_tasks() -> str:
    return await quart.render_template("tasks.html")


@admin.BLUEPRINT.route("/toggle-view", methods=["GET"])
async def admin_toggle_admin_view_page() -> str:
    """Display the page with a button to toggle between admin and user views."""
    empty_form = await util.EmptyForm.create_form()
    return await quart.render_template("toggle-admin-view.html", empty_form=empty_form)


@admin.BLUEPRINT.route("/toggle-admin-view", methods=["POST"])
async def admin_toggle_view() -> response.Response:
    await util.validate_empty_form()

    web_session = await session.read()
    if web_session is None:
        # For the type checker
        # We should pass this as an argument, then it's guaranteed
        raise base.ASFQuartException("Not authenticated", 401)
    user_uid = web_session.uid
    if user_uid is None:
        raise base.ASFQuartException("Invalid session, uid is None", 500)

    app = asfquart.APP
    if not hasattr(app, "app_id") or not isinstance(app.app_id, str):
        raise TypeError("Internal error: APP has no valid app_id")

    cookie_id = app.app_id
    session_dict = quart.session.get(cookie_id, {})
    downgrade = not session_dict.get("downgrade_admin_to_user", False)
    session_dict["downgrade_admin_to_user"] = downgrade

    message = "Viewing as regular user" if downgrade else "Viewing as admin"
    await quart.flash(message, "success")
    referrer = quart.request.referrer
    return quart.redirect(referrer or quart.url_for("admin.admin_data"))


@admin.BLUEPRINT.route("/ongoing-tasks/<project_name>/<version_name>/<revision>")
async def ongoing_tasks(project_name: str, version_name: str, revision: str) -> quart.wrappers.response.Response:
    try:
        ongoing = await interaction.tasks_ongoing(project_name, version_name, revision)
        return quart.Response(str(ongoing), mimetype="text/plain")
    except Exception:
        _LOGGER.exception(f"Error fetching ongoing task count for {project_name} {version_name} rev {revision}:")
        return quart.Response("", mimetype="text/plain")


async def _delete_release_data(release_name: str) -> None:
    """Handle the deletion of database records and filesystem data for a release."""
    async with db.session() as data:
        release = await data.release(name=release_name).demand(
            base.ASFQuartException(f"Release '{release_name}' not found.", 404)
        )
        release_dir = util.release_directory_base(release)

        # Delete from the database
        _LOGGER.info("Deleting database records for release: %s", release_name)
        # Cascade should handle this, but we delete manually anyway
        tasks_to_delete = await data.task(release_name=release_name).all()
        for task in tasks_to_delete:
            await data.delete(task)
        _LOGGER.debug("Deleted %d tasks for %s", len(tasks_to_delete), release_name)

        checks_to_delete = await data.check_result(release_name=release_name).all()
        for check in checks_to_delete:
            await data.delete(check)
        _LOGGER.debug("Deleted %d check results for %s", len(checks_to_delete), release_name)

        await data.ns_text_del_all(release_name + " draft")
        await data.ns_text_del_all(release_name + " preview")
        _LOGGER.debug("Deleted parent links for %s", release_name)

        await data.delete(release)
        _LOGGER.info("Deleted release record: %s", release_name)
        await data.commit()

    # Delete from the filesystem
    try:
        if await aiofiles.os.path.isdir(release_dir):
            _LOGGER.info("Deleting filesystem directory: %s", release_dir)
            # Believe this to be another bug in mypy Protocol handling
            # TODO: Confirm that this is a bug, and report upstream
            await aioshutil.rmtree(release_dir)  # type: ignore[call-arg]
            _LOGGER.info("Successfully deleted directory: %s", release_dir)
        else:
            _LOGGER.warning("Filesystem directory not found, skipping deletion: %s", release_dir)
    except Exception as e:
        _LOGGER.exception("Error deleting filesystem directory %s:", release_dir)
        await quart.flash(
            f"Database records for '{release_name}' deleted, but failed to delete filesystem directory: {e!s}",
            "warning",
        )


async def _update_committees() -> tuple[int, int]:  # noqa: C901
    ldap_projects = await apache.get_ldap_projects_data()
    projects = await apache.get_projects_data()
    podlings_data = await apache.get_current_podlings_data()
    committees = await apache.get_active_committee_data()

    ldap_projects_by_name: Mapping[str, apache.LDAPProject] = {p.name: p for p in ldap_projects.projects}
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
                    # Create the associated podling project
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

            # Add projects and associate them with the right PMC
            for project_name, project_status in projects.items():
                # FIXME: this is a quick workaround for inconsistent data wrt webservices PMC / projects
                #        the PMC seems to be identified by the key ws, but the associated projects use webservices
                if project_name.startswith("webservices-"):
                    project_name = project_name.replace("webservices-", "ws-")
                    project_status.pmc = "ws"

                # TODO: Annotator is in both projects and ldap_projects
                # The projects version is called "incubator-annotator", with "incubator" as its pmc
                # This is not detected by us as incubating, because we create those above
                # ("Create the associated podling project")
                # Since the Annotator project is in ldap_projects, we can just skip it here
                # Originally reported in https://github.com/apache/tooling-trusted-release/issues/35
                # Ideally it would be removed from the upstream data source, which is:
                # https://projects.apache.org/json/foundation/projects.json
                if project_name == "incubator-annotator":
                    continue

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
                tooling_committee = models.Committee(name="tooling", full_name="Tooling")
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
