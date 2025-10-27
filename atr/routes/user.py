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

from __future__ import annotations

from typing import TYPE_CHECKING

import quart

import atr.forms as forms
import atr.htm as htm
import atr.route as route
import atr.template as template
import atr.util as util

if TYPE_CHECKING:
    import werkzeug.wrappers.response as response


class CacheForm(forms.Typed):
    cache_submit = forms.submit("Cache me!")


class DeleteCacheForm(forms.Typed):
    delete_submit = forms.submit("Delete my cache")


@route.committer("/user/cache", methods=["GET"])
async def cache_get(session: route.CommitterSession) -> str:
    cache_form = await CacheForm.create_form()
    delete_cache_form = await DeleteCacheForm.create_form()

    cache_data = await util.session_cache_read()
    user_cached = session.uid in cache_data

    block = htm.Block()

    block.h1["Session cache management"]

    block.p[
        """This page allows you to cache your ASFQuart session information for use in
        contexts where web authentication is not available, such as SSH and rsync, the
        API, and background tasks. This is intended for developers only."""
    ]

    if user_cached:
        cached_entry = cache_data[session.uid]
        block.h2["Your cached session"]
        block.p["Your session is currently cached."]

        tbody = htm.Block(htm.tbody)
        tbody.append(htm.tr[htm.th["User ID"], htm.td[session.uid]])
        if "fullname" in cached_entry:
            tbody.append(htm.tr[htm.th["Full name"], htm.td[cached_entry["fullname"]]])
        if "email" in cached_entry:
            tbody.append(htm.tr[htm.th["Email"], htm.td[cached_entry["email"]]])
        if "pmcs" in cached_entry:
            committees = ", ".join(cached_entry["pmcs"]) if cached_entry["pmcs"] else "-"
            tbody.append(htm.tr[htm.th["Committees"], htm.td[committees]])
        if "projects" in cached_entry:
            projects = ", ".join(cached_entry["projects"]) if cached_entry["projects"] else "-"
            tbody.append(htm.tr[htm.th["Projects"], htm.td[projects]])

        block.table(".table.table-striped.table-bordered")[tbody.collect()]

        block.h3["Delete cache"]
        block.p["Remove your cached session information:"]
        delete_form_element = forms.render_simple(
            delete_cache_form,
            action=quart.request.path,
            submit_classes="btn-danger",
        )
        block.append(delete_form_element)
    else:
        block.h2["No cached session"]
        block.p["Your session is not currently cached."]

        block.h3["Cache current session"]
        block.p["Press the button below to cache your current session information:"]
        cache_form_element = forms.render_simple(
            cache_form,
            action=quart.request.path,
            submit_classes="btn-primary",
        )
        block.append(cache_form_element)

    return await template.blank("Session cache management", content=block.collect())


@route.committer("/user/cache", methods=["POST"])
async def session_post(session: route.CommitterSession) -> response.Response:
    form_data = await quart.request.form

    cache_form = await CacheForm.create_form(data=form_data)
    delete_cache_form = await DeleteCacheForm.create_form(data=form_data)

    if cache_form.cache_submit.data:
        await _cache_session(session)
        await quart.flash("Your session has been cached successfully", "success")
    elif delete_cache_form.delete_submit.data:
        await _delete_session_cache(session)
        await quart.flash("Your cached session has been deleted", "success")
    else:
        await quart.flash("Invalid form submission", "error")

    return await session.redirect(cache_get)


async def _cache_session(session: route.CommitterSession) -> None:
    cache_data = await util.session_cache_read()

    session_data = {
        "uid": session.uid,
        "dn": getattr(session, "dn", None),
        "fullname": getattr(session, "fullname", None),
        "email": getattr(session, "email", f"{session.uid}@apache.org"),
        "isMember": getattr(session, "isMember", False),
        "isChair": getattr(session, "isChair", False),
        "isRoot": getattr(session, "isRoot", False),
        "pmcs": getattr(session, "committees", []),
        "projects": getattr(session, "projects", []),
        "mfa": getattr(session, "mfa", False),
        "roleaccount": getattr(session, "isRole", False),
        "metadata": getattr(session, "metadata", {}),
    }

    cache_data[session.uid] = session_data

    await util.session_cache_write(cache_data)


async def _delete_session_cache(session: route.CommitterSession) -> None:
    cache_data = await util.session_cache_read()

    if session.uid in cache_data:
        del cache_data[session.uid]
        await util.session_cache_write(cache_data)
