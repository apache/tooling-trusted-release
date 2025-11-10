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
import hashlib
import secrets
from typing import Final

import quart

import atr.blueprints.post as post
import atr.get as get
import atr.htm as htm
import atr.jwtoken as jwtoken
import atr.shared as shared
import atr.storage as storage
import atr.util as util
import atr.web as web

_EXPIRY_DAYS: Final[int] = 180


@post.committer("/tokens/jwt")
async def jwt_post(session: web.Committer) -> web.QuartResponse:
    await util.validate_empty_form()

    jwt_token = jwtoken.issue(session.uid)
    return web.TextResponse(jwt_token)


@post.committer("/tokens")
@post.form(shared.tokens.TokenForm)
async def tokens(session: web.Committer, token_form: shared.tokens.TokenForm) -> web.WerkzeugResponse:
    match token_form:
        case shared.tokens.AddTokenForm() as add_form:
            return await _add_token(session, add_form)

        case shared.tokens.DeleteTokenForm() as delete_form:
            return await _delete_token(session, delete_form)


async def _add_token(session: web.Committer, add_form: shared.tokens.AddTokenForm) -> web.WerkzeugResponse:
    plaintext = secrets.token_urlsafe(32)
    token_hash = hashlib.sha3_256(plaintext.encode()).hexdigest()
    created = datetime.datetime.now(datetime.UTC)
    expires = created + datetime.timedelta(days=_EXPIRY_DAYS)

    async with storage.write() as write:
        wafc = write.as_foundation_committer()
        await wafc.tokens.add_token(
            session.uid,
            token_hash,
            created,
            expires,
            add_form.label or None,
        )

    await web.flash_success(
        htm.p[
            htm.strong["Your new token"],
            " is ",
            htm.code(".bg-light.border.rounded.px-1")[plaintext],
        ],
        htm.p(".mb-0")["Copy it now as you will not be able to see it again."],
    )
    return await session.redirect(get.tokens.tokens)


async def _delete_token(session: web.Committer, delete_form: shared.tokens.DeleteTokenForm) -> web.WerkzeugResponse:
    async with storage.write(session) as write:
        wafc = write.as_foundation_committer()
        await wafc.tokens.delete_token(delete_form.token_id)
    await quart.flash("Token deleted successfully", "success")
    return await session.redirect(get.tokens.tokens)
