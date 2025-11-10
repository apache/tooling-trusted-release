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

import quart

import atr.blueprints.post as post
import atr.get as get
import atr.shared as shared
import atr.util as util
import atr.web as web


@post.committer("/user/cache")
@post.form(shared.user.UserCacheForm)
async def session_post(session: web.Committer, user_cache_form: shared.user.UserCacheForm) -> web.WerkzeugResponse:
    match user_cache_form:
        case shared.user.CacheUserForm():
            await _cache_session(session)
            await quart.flash("Your session has been cached successfully", "success")

        case shared.user.DeleteCacheForm():
            await _delete_session_cache(session)
            await quart.flash("Your cached session has been deleted", "success")

    return await session.redirect(get.user.cache_get)


async def _cache_session(session: web.Committer) -> None:
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


async def _delete_session_cache(session: web.Committer) -> None:
    cache_data = await util.session_cache_read()

    if session.uid in cache_data:
        del cache_data[session.uid]
        await util.session_cache_write(cache_data)
