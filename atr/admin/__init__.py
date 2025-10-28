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

import asyncio
import collections
import os
import pathlib
import statistics
import sys
import time
from collections.abc import Callable, Mapping
from typing import Any, Final, Literal

import aiofiles.os
import aiohttp
import asfquart
import asfquart.base as base
import asfquart.session
import quart
import sqlalchemy.orm as orm
import werkzeug.wrappers.response as response

import atr.blueprints.admin as admin
import atr.config as config
import atr.datasources.apache as apache
import atr.db as db
import atr.db.interaction as interaction
import atr.forms as forms
import atr.get as get
import atr.ldap as ldap
import atr.log as log
import atr.mapping as mapping
import atr.models.sql as sql
import atr.principal as principal
import atr.storage as storage
import atr.storage.outcome as outcome
import atr.storage.types as types
import atr.tasks as tasks
import atr.template as template
import atr.util as util
import atr.validate as validate
import atr.web as web

ROUTES_MODULE: Final[Literal[True]] = True


class BrowseAsUserForm(forms.Typed):
    """Form for browsing as another user."""

    uid = forms.string("ASF UID", placeholder="Enter the ASF UID to browse as")
    submit = forms.submit("Browse as this user")


class CheckKeysForm(forms.Typed):
    submit = forms.submit("Check public signing key details")


class DeleteCommitteeKeysForm(forms.Typed):
    committee_name = forms.select("Committee")
    confirm_delete = forms.string(
        "Confirmation",
        validators=forms.constant("DELETE KEYS"),
        placeholder="DELETE KEYS",
    )
    submit = forms.submit("Delete all keys for selected committee")


class DeleteReleaseForm(forms.Typed):
    """Form for deleting releases."""

    confirm_delete = forms.string(
        "Confirmation",
        validators=forms.constant("DELETE"),
        placeholder="DELETE",
        description="Please type DELETE exactly to confirm deletion.",
    )
    submit = forms.submit("Delete selected releases permanently")


class DeleteTestKeysForm(forms.Typed):
    submit = forms.submit("Delete all OpenPGP keys for test user")


class LdapLookupForm(forms.Typed):
    uid = forms.optional("ASF UID (optional)", placeholder="Enter ASF UID, e.g. johnsmith, or * for all")
    email = forms.optional("Email address (optional)", placeholder="Enter email address, e.g. user@example.org")
    submit = forms.submit("Lookup")


class RegenerateKeysForm(forms.Typed):
    submit = forms.submit("Regenerate all KEYS files")


@admin.get("/all-releases")
async def all_releases(session: web.Committer) -> str:
    """Display a list of all releases across all phases."""
    async with db.session() as data:
        releases = await data.release(_project=True, _committee=True).order_by(sql.Release.name).all()
    return await template.render("all-releases.html", releases=releases, release_as_url=mapping.release_as_url)


@admin.get("/browse-as")
async def browse_as_get(session: web.Committer) -> str | response.Response:
    return await _browse_as(session)


@admin.post("/browse-as")
async def browse_as_post(session: web.Committer) -> str | response.Response:
    return await _browse_as(session)


async def _browse_as(session: web.Committer) -> str | response.Response:
    """Allows an admin to browse as another user."""
    # TODO: Enable this in debugging mode only?
    import atr.get.root as root

    form = await BrowseAsUserForm.create_form()
    if not (await form.validate_on_submit()):
        return await template.render("browse-as.html", form=form)

    new_uid = str(util.unwrap(form.uid.data))
    if not (current_session := await asfquart.session.read()):
        raise base.ASFQuartException("Not authenticated", 401)

    bind_dn, bind_password = principal.get_ldap_bind_dn_and_password()
    ldap_params = ldap.SearchParameters(
        uid_query=new_uid,
        bind_dn_from_config=bind_dn,
        bind_password_from_config=bind_password,
    )
    await asyncio.to_thread(ldap.search, ldap_params)

    if not ldap_params.results_list:
        await quart.flash(f"User '{new_uid}' not found in LDAP.", "error")
        return await session.redirect(browse_as_get)

    ldap_projects_data = await apache.get_ldap_projects_data()
    committee_data = await apache.get_active_committee_data()
    ldap_data = ldap_params.results_list[0]
    log.info("Current ASFQuart session data: %s", current_session)
    new_session_data = _session_data(
        ldap_data,
        new_uid,
        current_session,
        ldap_projects_data,
        committee_data,
        bind_dn,
        bind_password,
    )
    log.info("New Quart cookie (not ASFQuart session) data: %s", new_session_data)
    asfquart.session.write(new_session_data)

    await quart.flash(
        f"You are now browsing as '{new_uid}'. To return to your own account, please log out and log back in.",
        "success",
    )
    return await session.redirect(root.index)


@admin.get("/configuration")
async def configuration(session: web.Committer) -> quart.wrappers.response.Response:
    """Display the current application configuration values."""

    conf = config.get()
    values: list[str] = []
    for name in dir(conf):
        if name.startswith("_"):
            continue
        try:
            val = getattr(conf, name)
        except Exception as exc:
            val = log.python_repr(f"error: {exc}")
        if name.endswith("_PASSWORD"):
            val = log.python_repr("redacted")
        if callable(val):
            continue
        values.append(f"{name}={val}")

    values.sort()
    return web.TextResponse("\n".join(values))


@admin.get("/consistency")
async def consistency(session: web.Committer) -> web.TextResponse:
    """Check for consistency between the database and the filesystem."""
    # Get all releases from the database
    async with db.session() as data:
        releases = await data.release().all()
    database_dirs = []
    for release in releases:
        path = util.release_directory_version(release)
        database_dirs.append(str(path))
    if len(set(database_dirs)) != len(database_dirs):
        raise base.ASFQuartException("Duplicate release directories in database", errorcode=500)

    # Get all releases from the filesystem
    filesystem_dirs = await _get_filesystem_dirs()

    # Pair them up where possible
    paired_dirs = []
    for database_dir in database_dirs[:]:
        for filesystem_dir in filesystem_dirs[:]:
            if database_dir == filesystem_dir:
                paired_dirs.append(database_dir)
                database_dirs.remove(database_dir)
                filesystem_dirs.remove(filesystem_dir)
                break
    return web.TextResponse(
        f"""\
=== BROKEN ===

DATABASE ONLY:

{"\n".join(sorted(database_dirs or ["-"]))}

FILESYSTEM ONLY:

{"\n".join(sorted(filesystem_dirs or ["-"]))}


== Okay ==

Paired correctly:

{"\n".join(sorted(paired_dirs or ["-"]))}
"""
    )


@admin.get("/data")
@admin.get("/data/<model>")
async def data(session: web.Committer, model: str = "Committee") -> str:
    """Browse all records in the database."""
    async with db.session() as data:
        # Map of model names to their classes
        # TODO: Add distribution channel, key link, and any others
        model_methods: dict[str, Callable[[], db.Query[Any]]] = {
            "CheckResult": data.check_result,
            "CheckResultIgnore": data.check_result_ignore,
            "Committee": data.committee,
            "Project": data.project,
            "PublicSigningKey": data.public_signing_key,
            "Release": data.release,
            "ReleasePolicy": data.release_policy,
            "Revision": data.revision,
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

        return await template.render(
            "data-browser.html", models=list(model_methods.keys()), model=model, records=records_dict
        )


@admin.get("/delete-test-openpgp-keys")
async def delete_test_openpgp_keys_get(session: web.Committer) -> quart.Response | response.Response:
    if not config.get().ALLOW_TESTS:
        raise base.ASFQuartException("Test operations are disabled in this environment", errorcode=403)

    delete_form = await DeleteTestKeysForm.create_form()
    rendered_form = forms.render_simple(delete_form, action="")
    return web.ElementResponse(rendered_form)


@admin.post("/delete-test-openpgp-keys")
async def delete_test_openpgp_keys_post(session: web.Committer) -> quart.Response | response.Response:
    """Delete all test user OpenPGP keys and their links."""
    if not config.get().ALLOW_TESTS:
        raise base.ASFQuartException("Test operations are disabled in this environment", errorcode=403)

    test_uid = "test"
    delete_form = await DeleteTestKeysForm.create_form()
    if not await delete_form.validate_on_submit():
        raise base.ASFQuartException("Invalid form submission. Please check your input and try again.", errorcode=400)

    async with storage.write() as write:
        wafc = write.as_foundation_committer()
        outcome = await wafc.keys.test_user_delete_all(test_uid)
        outcome.result_or_raise()

    return await session.redirect(get.keys.keys)


@admin.get("/delete-committee-keys")
async def delete_committee_keys_get(session: web.Committer) -> str | response.Response:
    return await _delete_committee_keys(session)


@admin.post("/delete-committee-keys")
async def delete_committee_keys_post(session: web.Committer) -> str | response.Response:
    return await _delete_committee_keys(session)


async def _delete_committee_keys(session: web.Committer) -> str | response.Response:
    form = await DeleteCommitteeKeysForm.create_form()
    async with db.session() as data:
        all_committees = await data.committee(_public_signing_keys=True).order_by(sql.Committee.name).all()
        committees_with_keys = [c for c in all_committees if c.public_signing_keys]
    form.committee_name.choices = [(c.name, c.display_name) for c in committees_with_keys]

    if await form.validate_on_submit():
        committee_name = form.committee_name.data
        async with db.session() as data:
            committee_query = data.committee(name=committee_name)
            via = sql.validate_instrumented_attribute
            committee_query.query = committee_query.query.options(
                orm.selectinload(via(sql.Committee.public_signing_keys)).selectinload(
                    via(sql.PublicSigningKey.committees)
                )
            )
            committee = await committee_query.get()

            if not committee:
                await quart.flash(f"Committee '{committee_name}' not found.", "error")
                return await session.redirect(delete_committee_keys_get)

            keys_to_check = list(committee.public_signing_keys)
            if not keys_to_check:
                await quart.flash(f"Committee '{committee_name}' has no keys.", "info")
                return await session.redirect(delete_committee_keys_get)

            num_removed = len(committee.public_signing_keys)
            committee.public_signing_keys.clear()
            await data.flush()

            unused_deleted = 0
            for key_obj in keys_to_check:
                if not key_obj.committees:
                    await data.delete(key_obj)
                    unused_deleted += 1

            await data.commit()
            await quart.flash(
                f"Removed {num_removed} key links for '{committee_name}'. Deleted {unused_deleted} unused keys.",
                "success",
            )
        return await session.redirect(delete_committee_keys_get)

    elif quart.request.method == "POST":
        await quart.flash("Form validation failed. Select committee and type DELETE KEYS.", "warning")

    return await template.render("delete-committee-keys.html", form=form)


@admin.get("/delete-release")
async def delete_release_get(session: web.Committer) -> str | response.Response:
    return await _delete_release(session)


@admin.post("/delete-release")
async def delete_release_post(session: web.Committer) -> str | response.Response:
    return await _delete_release(session)


async def _delete_release(session: web.Committer) -> str | response.Response:
    """Page to delete selected releases and their associated data and files."""
    form = await DeleteReleaseForm.create_form()

    if quart.request.method == "POST":
        if await form.validate_on_submit():
            form_data = await quart.request.form
            releases_to_delete = form_data.getlist("releases_to_delete")

            if not releases_to_delete:
                await quart.flash("No releases selected for deletion.", "warning")
                return await session.redirect(delete_release_get)

            await _delete_releases(session, releases_to_delete)

            # Redirecting back to the deletion page will refresh the list of releases too
            return await session.redirect(delete_release_get)

        # It's unlikely that form validation failed due to spurious release names
        # Therefore we assume that the user forgot to type DELETE to confirm
        await quart.flash("Form validation failed. Please type DELETE to confirm.", "warning")
        # Fall through to the combined GET and failed form validation handling below

    # For GET request or failed form validation
    async with db.session() as data:
        releases = await data.release(_project=True).order_by(sql.Release.name).all()
    return await template.render("delete-release.html", form=form, releases=releases, stats=None)


@admin.get("/env")
async def env(session: web.Committer) -> quart.wrappers.response.Response:
    """Display the environment variables."""
    env_vars = []
    for key, value in os.environ.items():
        env_vars.append(f"{key}={value}")
    return web.TextResponse("\n".join(env_vars))


@admin.get("/keys/check")
async def keys_check_get(session: web.Committer) -> quart.Response:
    return await _keys_check(session)


@admin.post("/keys/check")
async def keys_check_post(session: web.Committer) -> quart.Response:
    return await _keys_check(session)


async def _keys_check(session: web.Committer) -> quart.Response:
    """Check public signing key details."""
    if quart.request.method != "POST":
        check_form = await CheckKeysForm.create_form()
        rendered_form = forms.render_simple(check_form, action="")
        return web.ElementResponse(rendered_form)

    try:
        result = await _check_keys()
        return web.TextResponse(result)
    except Exception as e:
        log.exception("Exception during key check:")
        return web.TextResponse(f"Exception during key check: {e!s}")


@admin.get("/keys/regenerate-all")
async def keys_regenerate_all_get(session: web.Committer) -> quart.Response:
    return await _keys_regenerate_all(session)


@admin.post("/keys/regenerate-all")
async def keys_regenerate_all_post(session: web.Committer) -> quart.Response:
    return await _keys_regenerate_all(session)


async def _keys_regenerate_all(session: web.Committer) -> quart.Response:
    """Regenerate the KEYS file for all committees."""
    if quart.request.method != "POST":
        regenerate_form = await RegenerateKeysForm.create_form()
        rendered_form = forms.render_simple(regenerate_form, action="")
        return web.ElementResponse(rendered_form)

    async with db.session() as data:
        committee_names = [c.name for c in await data.committee().all()]

    outcomes = outcome.List[str]()
    async with storage.write() as write:
        for committee_name in committee_names:
            wacm_outcome = write.as_committee_member_outcome(committee_name)
            wacm = wacm_outcome.result_or_none()
            if wacm is None:
                continue
            outcomes.append(await wacm.keys.autogenerate_keys_file())

    response_lines = []
    for ocr in outcomes.results():
        response_lines.append(f"Regenerated: {ocr}")
    for oce in outcomes.errors():
        response_lines.append(f"Error regenerating: {type(oce).__name__} {oce}")

    return web.TextResponse("\n".join(response_lines))


@admin.get("/keys/update")
async def keys_update_get(session: web.Committer) -> str | response.Response | tuple[Mapping[str, Any], int]:
    return await _keys_update(session)


@admin.post("/keys/update")
async def keys_update_post(session: web.Committer) -> str | response.Response | tuple[Mapping[str, Any], int]:
    return await _keys_update(session)


async def _keys_update(session: web.Committer) -> str | response.Response | tuple[Mapping[str, Any], int]:
    """Update keys from remote data."""
    if quart.request.method != "POST":
        empty_form = await forms.Empty.create_form()
        # Get the previous output from the log file
        log_path = pathlib.Path("keys_import.log")
        if not await aiofiles.os.path.exists(log_path):
            previous_output = None
        else:
            async with aiofiles.open(log_path) as f:
                previous_output = await f.read()
        return await template.render("update-keys.html", empty_form=empty_form, previous_output=previous_output)

    try:
        pid = await _update_keys(session.asf_uid)
        return {
            "message": f"Successfully started key update process with PID {pid}",
            "category": "success",
        }, 200
    except Exception as e:
        log.exception("Failed to start key update process")
        return {
            "message": f"Failed to update keys: {e!s}",
            "category": "error",
        }, 200


@admin.get("/ldap/")
async def ldap_get(session: web.Committer) -> str:
    return await _ldap(session)


@admin.post("/ldap/")
async def ldap_post(session: web.Committer) -> str:
    return await _ldap(session)


async def _ldap(session: web.Committer) -> str:
    form = await LdapLookupForm.create_form(data=quart.request.args)

    uid_query = form.uid.data
    email_query = form.email.data

    ldap_params: ldap.SearchParameters | None = None
    if (quart.request.method == "GET") and (uid_query or email_query):
        bind_dn = quart.current_app.config.get("LDAP_BIND_DN")
        bind_password = quart.current_app.config.get("LDAP_BIND_PASSWORD")

        start = time.perf_counter_ns()
        ldap_params = ldap.SearchParameters(
            uid_query=uid_query,
            email_query=email_query,
            bind_dn_from_config=bind_dn,
            bind_password_from_config=bind_password,
            email_only=False,
        )
        await asyncio.to_thread(ldap.search, ldap_params)
        end = time.perf_counter_ns()
        log.info("LDAP search took %d ms", (end - start) / 1000000)

    return await template.render(
        "ldap-lookup.html",
        form=form,
        ldap_params=ldap_params,
        asf_id=session.asf_uid,
        ldap_query_performed=ldap_params is not None,
        uid_query=uid_query,
    )


@admin.get("/ongoing-tasks/<project_name>/<version_name>/<revision>")
async def ongoing_tasks_get(
    session: web.Committer, project_name: str, version_name: str, revision: str
) -> quart.wrappers.response.Response:
    return await _ongoing_tasks(session, project_name, version_name, revision)


@admin.post("/ongoing-tasks/<project_name>/<version_name>/<revision>")
async def ongoing_tasks_post(
    session: web.Committer, project_name: str, version_name: str, revision: str
) -> quart.wrappers.response.Response:
    return await _ongoing_tasks(session, project_name, version_name, revision)


async def _ongoing_tasks(
    session: web.Committer, project_name: str, version_name: str, revision: str
) -> quart.wrappers.response.Response:
    try:
        ongoing = await interaction.tasks_ongoing(project_name, version_name, revision)
        return web.TextResponse(str(ongoing))
    except Exception:
        log.exception(f"Error fetching ongoing task count for {project_name} {version_name} rev {revision}:")
        return web.TextResponse("")


@admin.get("/performance")
async def performance(session: web.Committer) -> str:
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
        return await template.render("performance.html", stats=None)

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
                log.error("Error parsing line: %s", line)
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
    return await template.render("performance.html", stats=sorted_summary)


@admin.get("/projects/update")
async def projects_update_get(session: web.Committer) -> str | response.Response | tuple[Mapping[str, Any], int]:
    return await _projects_update(session)


@admin.post("/projects/update")
async def projects_update_post(session: web.Committer) -> str | response.Response | tuple[Mapping[str, Any], int]:
    return await _projects_update(session)


async def _projects_update(session: web.Committer) -> str | response.Response | tuple[Mapping[str, Any], int]:
    """Update projects from remote data."""
    if quart.request.method == "POST":
        try:
            task = await tasks.metadata_update(session.asf_uid)
            return {
                "message": f"Metadata update task has been queued with ID {task.id}.",
                "category": "success",
            }, 200
        except Exception as e:
            log.exception("Failed to queue metadata update task")
            return {
                "message": f"Failed to queue metadata update: {e!s}",
                "category": "error",
            }, 200

    # For GET requests, show the update form
    empty_form = await forms.Empty.create_form()
    return await template.render("update-projects.html", empty_form=empty_form)


@admin.get("/tasks")
async def tasks_(session: web.Committer) -> str:
    return await template.render("tasks.html")


@admin.get("/task-times/<project_name>/<version_name>/<revision_number>")
async def task_times(
    session: web.Committer, project_name: str, version_name: str, revision_number: str
) -> quart.wrappers.response.Response:
    values = []
    async with db.session() as data:
        tasks = await data.task(
            project_name=project_name, version_name=version_name, revision_number=revision_number
        ).all()  # type: ignore[reportOptionalMemberAccess]
        for task in tasks:
            if (task.started is None) or (task.completed is None):
                continue
            ms_elapsed = (task.completed - task.started).total_seconds() * 1000
            values.append(f"{task.task_type} {ms_elapsed:.2f}ms")

    return web.TextResponse("\n".join(values))


@admin.get("/test")
async def test(session: web.Committer) -> quart.wrappers.response.Response:
    """Test the storage layer."""
    import atr.storage as storage

    async with aiohttp.ClientSession() as aiohttp_client_session:
        url = "https://downloads.apache.org/zeppelin/KEYS"
        async with aiohttp_client_session.get(url) as response:
            keys_file_text = await response.text()

    async with storage.write(session) as write:
        wacm = write.as_committee_member("tooling")
        start = time.perf_counter_ns()
        outcomes: outcome.List[types.Key] = await wacm.keys.ensure_stored(keys_file_text)
        end = time.perf_counter_ns()
        log.info(f"Upload of {outcomes.result_count} keys took {end - start} ns")
    for ocr in outcomes.results():
        log.info(f"Uploaded key: {type(ocr)} {ocr.key_model.fingerprint}")
    for oce in outcomes.errors():
        log.error(f"Error uploading key: {type(oce)} {oce}")
    parsed_count = outcomes.result_predicate_count(lambda k: k.status == types.KeyStatus.PARSED)
    inserted_count = outcomes.result_predicate_count(lambda k: k.status == types.KeyStatus.INSERTED)
    linked_count = outcomes.result_predicate_count(lambda k: k.status == types.KeyStatus.LINKED)
    inserted_and_linked_count = outcomes.result_predicate_count(
        lambda k: k.status == types.KeyStatus.INSERTED_AND_LINKED
    )
    log.info(f"Parsed: {parsed_count}")
    log.info(f"Inserted: {inserted_count}")
    log.info(f"Linked: {linked_count}")
    log.info(f"InsertedAndLinked: {inserted_and_linked_count}")
    return web.TextResponse(str(wacm))


@admin.get("/toggle-view")
async def toggle_view_get(session: web.Committer) -> str:
    """Display the page with a button to toggle between admin and user views."""
    empty_form = await forms.Empty.create_form()
    return await template.render("toggle-admin-view.html", empty_form=empty_form)


@admin.post("/toggle-view")
async def toggle_view_post(session: web.Committer) -> response.Response:
    await util.validate_empty_form()

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
    return quart.redirect(referrer or util.as_url(data))


@admin.get("/validate")
async def validate_(session: web.Committer) -> str:
    """Run validators and display any divergences."""

    async with db.session() as data:
        divergences = [d async for d in validate.everything(data)]

    return await template.render(
        "validation.html",
        divergences=divergences,
    )


async def _check_keys(fix: bool = False) -> str:
    email_to_uid = await util.email_to_uid_map()
    bad_keys = []
    async with db.session() as data:
        keys = await data.public_signing_key().all()
        for key in keys:
            uids = []
            if key.primary_declared_uid:
                uids.append(key.primary_declared_uid)
            if key.secondary_declared_uids:
                uids.extend(key.secondary_declared_uids)
            asf_uid = await util.asf_uid_from_uids(uids, ldap_data=email_to_uid)
            if asf_uid != key.apache_uid:
                bad_keys.append(f"{key.fingerprint} detected: {asf_uid}, key: {key.apache_uid}")
            if fix:
                key.apache_uid = asf_uid
                await data.commit()
    message = f"Checked {len(keys)} keys"
    if bad_keys:
        message += f"\nFound {len(bad_keys)} bad keys:\n{'\n'.join(bad_keys)}"
    return message


async def _delete_releases(session: web.Committer, releases_to_delete: list[str]) -> None:
    success_count = 0
    fail_count = 0
    error_messages = []

    for release_name in releases_to_delete:
        try:
            async with db.session() as data:
                release = await data.release(name=release_name, _committee=True, _project=True).demand(
                    RuntimeError(f"Release {release_name} not found")
                )
                if release.committee is None:
                    raise RuntimeError(f"Release {release_name} has no committee")
            async with storage.write(session) as write:
                wafa = write.as_foundation_admin(release.committee.name)
                await wafa.release.delete(release.project.name, release.version)
            success_count += 1
        except base.ASFQuartException as e:
            log.error(f"Error deleting release {release_name}: {e}")
            fail_count += 1
            error_messages.append(f"{release_name}: {e}")
        except Exception as e:
            log.exception(f"Unexpected error deleting release {release_name}:")
            fail_count += 1
            error_messages.append(f"{release_name}: Unexpected error ({e})")

    if success_count > 0:
        await quart.flash(f"Successfully deleted {success_count} release(s).", "success")
    if fail_count > 0:
        errors_str = "\n".join(error_messages)
        await quart.flash(f"Failed to delete {fail_count} release(s):\n{errors_str}", "error")


async def _get_filesystem_dirs() -> list[str]:
    filesystem_dirs = []
    await _get_filesystem_dirs_finished(filesystem_dirs)
    await _get_filesystem_dirs_unfinished(filesystem_dirs)
    return filesystem_dirs


async def _get_filesystem_dirs_finished(filesystem_dirs: list[str]) -> None:
    finished_dir = util.get_finished_dir()
    finished_dir_contents = await aiofiles.os.listdir(finished_dir)
    for project_dir in finished_dir_contents:
        project_dir_path = os.path.join(finished_dir, project_dir)
        if await aiofiles.os.path.isdir(project_dir_path):
            for version_dir in await aiofiles.os.listdir(project_dir_path):
                if await aiofiles.os.path.isdir(os.path.join(project_dir_path, version_dir)):
                    version_dir_path = os.path.join(project_dir_path, version_dir)
                    if await aiofiles.os.path.isdir(version_dir_path):
                        filesystem_dirs.append(version_dir_path)


async def _get_filesystem_dirs_unfinished(filesystem_dirs: list[str]) -> None:
    unfinished_dir = util.get_unfinished_dir()
    unfinished_dir_contents = await aiofiles.os.listdir(unfinished_dir)
    for project_dir in unfinished_dir_contents:
        project_dir_path = os.path.join(unfinished_dir, project_dir)
        if await aiofiles.os.path.isdir(project_dir_path):
            for version_dir in await aiofiles.os.listdir(project_dir_path):
                if await aiofiles.os.path.isdir(os.path.join(project_dir_path, version_dir)):
                    version_dir_path = os.path.join(project_dir_path, version_dir)
                    if await aiofiles.os.path.isdir(version_dir_path):
                        filesystem_dirs.append(version_dir_path)


def _get_user_committees_from_ldap(uid: str, bind_dn: str, bind_password: str) -> set[str]:
    with ldap.Search(bind_dn, bind_password) as ldap_search:
        result = ldap_search.search(
            ldap_base="ou=project,ou=groups,dc=apache,dc=org",
            ldap_scope="SUBTREE",
            ldap_query=f"(|(ownerUid={uid})(owner=uid={uid},ou=people,dc=apache,dc=org))",
            ldap_attrs=["cn"],
        )

    committees = set()
    for hit in result:
        if not isinstance(hit, dict):
            continue
        pmc = hit.get("cn")
        if not (isinstance(pmc, list) and (len(pmc) == 1)):
            continue
        project_name = pmc[0]
        if project_name and isinstance(project_name, str):
            committees.add(project_name)

    return committees


def _session_data(
    ldap_data: dict[str, Any],
    new_uid: str,
    current_session: asfquart.session.ClientSession,
    ldap_projects: apache.LDAPProjectsData,
    committee_data: apache.CommitteeData,
    bind_dn: str,
    bind_password: str,
) -> dict[str, Any]:
    # This is not quite accurate
    # For example, this misses "tooling" for tooling members
    projects = {p.name for p in ldap_projects.projects if (new_uid in p.members) or (new_uid in p.owners)}
    # And this adds "incubator", which is not in the OAuth data
    committees = _get_user_committees_from_ldap(new_uid, bind_dn, bind_password)

    # Or asf-member-status?
    is_member = bool(projects or committees)
    is_root = False
    is_chair = any(new_uid in (user.id for user in c.chair) for c in committee_data.committees)

    return {
        "uid": ldap_data.get("uid", [new_uid])[0],
        "dn": None,
        "fullname": ldap_data.get("cn", [new_uid])[0],
        # "email": ldap_user.get("mail", [""])[0],
        # Or asf-committer-email?
        "email": f"{new_uid}@apache.org",
        "isMember": is_member,
        "isChair": is_chair,
        "isRoot": is_root,
        # WARNING: ASFQuart session.ClientSession uses "committees"
        # But this is cookie, not ClientSession, data, and requires "pmcs"
        "pmcs": sorted(list(committees)),
        "projects": sorted(list(projects)),
        "mfa": current_session.mfa,
        "isRole": False,
        "metadata": {},
    }


async def _update_keys(asf_uid: str) -> int:
    async def _log_process(process: asyncio.subprocess.Process) -> None:
        try:
            stdout, stderr = await process.communicate()
            if stdout:
                log.info(f"keys_import.py stdout:\n{stdout.decode('utf-8')[:1000]}")
            if stderr:
                log.error(f"keys_import.py stderr:\n{stderr.decode('utf-8')[:1000]}")
        except Exception:
            log.exception("Error reading from subprocess for keys_import.py")

    app = asfquart.APP
    if not hasattr(app, "background_tasks"):
        app.background_tasks = set()

    if await aiofiles.os.path.exists("../Dockerfile.alpine"):
        # Not in a container, developing locally
        command = ["poetry", "run", "python3", "scripts/keys_import.py", asf_uid]
    else:
        # In a container
        command = [sys.executable, "scripts/keys_import.py", asf_uid]

    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=".."
    )

    task = asyncio.create_task(_log_process(process))
    app.background_tasks.add(task)
    task.add_done_callback(app.background_tasks.discard)

    return process.pid
