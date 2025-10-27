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
import time
from typing import Final

import markupsafe
import quart
import sqlmodel
import werkzeug.datastructures as datastructures
import werkzeug.wrappers.response as response
import wtforms.fields.core as core

import atr.db as db
import atr.forms as forms
import atr.htm as htm
import atr.jwtoken as jwtoken
import atr.log as log
import atr.models.sql as sql
import atr.route as route
import atr.storage as storage
import atr.template as templates
import atr.util as util
import atr.web as web

_EXPIRY_DAYS: Final[int] = 180


type Fragment = htm.Element | core.Field | str


class AddTokenForm(forms.Typed):
    label = forms.string("Label", optional=True, validators=forms.length(max=100), placeholder="E.g. CI bot")
    submit = forms.submit("Generate token")


class DeleteTokenForm(forms.Typed):
    token_id = forms.hidden()
    submit = forms.submit("Delete")


class IssueJWTForm(forms.Typed):
    submit = forms.submit("Generate JWT")


@route.committer("/tokens/jwt", methods=["POST"])
async def jwt_post(session: route.CommitterSession) -> quart.Response:
    await util.validate_empty_form()

    jwt_token = jwtoken.issue(session.uid)
    return web.TextResponse(jwt_token)


@route.committer("/tokens", methods=["GET", "POST"])
async def tokens(session: route.CommitterSession) -> str | response.Response:
    request_form = await quart.request.form

    if is_post := quart.request.method == "POST":
        maybe_response = await _handle_post(session, request_form)
        if maybe_response is not None:
            return maybe_response

    add_form = await AddTokenForm.create_form(data=request_form if is_post else None)
    issue_form = await IssueJWTForm.create_form(data=request_form if is_post else None)

    start = time.perf_counter_ns()
    async with storage.read_as_foundation_committer() as rafc:
        tokens_list = await rafc.tokens.own_personal_access_tokens()
        most_recent_pat = await rafc.tokens.most_recent_jwt_pat()
    end = time.perf_counter_ns()
    log.info("Tokens list fetched in %dms", (end - start) / 1_000_000)

    start = time.perf_counter_ns()
    add_form_elem = _build_add_form_element(add_form)
    issue_form_elem = _build_issue_jwt_form_element(issue_form)
    tokens_table = _build_tokens_table(tokens_list)

    issue_jwt = [
        htm.p[
            """Generate a JSON Web Token (JWT) to authenticate calls to ATR's
            private API routes. Treat the token like a password and include it
            in the Authorization header as a Bearer token when invoking the
            protected endpoints."""
            # p["Example"],
        ],
        issue_form_elem,
        htm.pre(id="jwt-output", class_="d-none mt-2 p-3 atr-word-wrap border rounded w-50"),
    ]

    if most_recent_pat and most_recent_pat.last_used:
        issue_jwt.append(
            htm.p(".mt-3")[
                "You most recently used a PAT to issue a JWT at ",
                htm.strong[util.format_datetime(most_recent_pat.last_used) + "Z"],
                ", using the PAT labelled ",
                htm.code[most_recent_pat.label or "[Untitled]"],
                ".",
            ]
        )

    content_elem = htm.div[
        htm.h1["Tokens"],
        htm.h2["Personal Access Tokens (PATs)"],
        htm.p[
            """Generate tokens for API access. For security, the plaintext
            token is shown only once when you create it. You can revoke tokens
            you no longer need."""
        ],
        htm.div(".card.mb-4")[
            htm.div(".card-header")["Generate new token"],
            htm.div(".card-body")[add_form_elem],
        ],
        tokens_table,
        htm.h2["JSON Web Token (JWT)"],
        htm.div[issue_jwt],
    ]
    end = time.perf_counter_ns()
    log.info("Content elem built in %dms", (end - start) / 1_000_000)

    start = time.perf_counter_ns()
    rendered = await templates.render(
        "blank.html",
        title="Tokens",
        description="Manage your PATs and JWTs.",
        content=content_elem,
        javascripts=[util.static_path("js", "create-a-jwt.js")],
    )
    end = time.perf_counter_ns()
    log.info("Rendered in %dms", (end - start) / 1_000_000)

    return rendered


def _as_markup(fragment: Fragment) -> markupsafe.Markup:
    return markupsafe.Markup(str(fragment))


def _build_add_form_element(a_form: AddTokenForm) -> markupsafe.Markup:
    elem = htm.form(method="post", action=util.as_url(tokens))[
        _as_markup(a_form.csrf_token),
        htm.div(".mb-3")[
            a_form.label.label,
            a_form.label(class_="form-control"),
        ],
        a_form.submit(class_="btn btn-primary"),
    ]
    return _as_markup(elem)


def _build_delete_form_element(token_id: int | None) -> markupsafe.Markup:
    d_form = DeleteTokenForm()
    d_form.token_id.data = "" if token_id is None else str(token_id)
    elem = htm.form(".mb-0", method="post", action=util.as_url(tokens))[
        _as_markup(d_form.csrf_token),
        _as_markup(d_form.token_id),
        d_form.submit(class_="btn btn-sm btn-danger"),
    ]
    return _as_markup(elem)


def _build_issue_jwt_form_element(j_form: IssueJWTForm) -> markupsafe.Markup:
    elem = htm.form("#issue-jwt-form", method="post", action=util.as_url(jwt_post))[
        _as_markup(j_form.csrf_token),
        j_form.submit(class_="btn btn-primary"),
    ]
    return _as_markup(elem)


def _build_tokens_table(tokens_list: list[sql.PersonalAccessToken]) -> markupsafe.Markup:
    if not tokens_list:
        return _as_markup(htm.p["No tokens found."])

    rows = [
        htm.tr(".align-middle")[
            htm.td[t.label or ""],
            htm.td[util.format_datetime(t.created)],
            htm.td[util.format_datetime(t.expires)],
            htm.td[util.format_datetime(t.last_used) if t.last_used else "Never"],
            htm.td[_build_delete_form_element(t.id)],
        ]
        for t in tokens_list
    ]

    table_elem = htm.table(".table.table-striped")[
        htm.thead[
            htm.tr[
                htm.th["Label"],
                htm.th["Created"],
                htm.th["Expires"],
                htm.th["Last used"],
                htm.th[""],
            ]
        ],
        htm.tbody[rows],
    ]
    return _as_markup(table_elem)


async def _create_token(uid: str, label: str | None) -> str:
    plaintext = secrets.token_urlsafe(32)
    token_hash = hashlib.sha3_256(plaintext.encode()).hexdigest()
    created = datetime.datetime.now(datetime.UTC)
    expires = created + datetime.timedelta(days=_EXPIRY_DAYS)

    async with storage.write() as write:
        wafc = write.as_foundation_committer()
        await wafc.tokens.add_token(uid, token_hash, created, expires, label)
    return plaintext


@db.session_commit_function
async def _delete_token(data: db.Session, uid: str, token_id: int) -> None:
    pat = await data.query_one_or_none(
        sqlmodel.select(sql.PersonalAccessToken).where(
            sql.PersonalAccessToken.id == token_id,
            sql.PersonalAccessToken.asfuid == uid,
        )
    )
    if pat:
        await data.delete(pat)


async def _handle_post(
    session: route.CommitterSession, request_form: datastructures.MultiDict
) -> response.Response | None:
    if "token_id" in request_form:
        return await _handle_delete_token_post(session, request_form)

    if "label" in request_form:
        return await _handle_add_token_post(session, request_form)

    return await _handle_issue_jwt_post(session, request_form)


async def _handle_add_token_post(
    session: route.CommitterSession, request_form: datastructures.MultiDict
) -> response.Response | None:
    add_form = await AddTokenForm.create_form(data=request_form)
    if await add_form.validate_on_submit():
        label_val = str(add_form.label.data) if add_form.label.data else None
        plaintext = await _create_token(session.uid, label_val)
        success_msg = htm.div[
            htm.p[
                htm.strong["Your new token"],
                " is ",
                htm.code(".bg-light.border.rounded.px-1")[plaintext],
            ],
            htm.p(".mb-0")["Copy it now as you will not be able to see it again."],
        ]
        await quart.flash(_as_markup(success_msg), "success")
        return await session.redirect(tokens)

    return None


async def _handle_delete_token_post(
    session: route.CommitterSession, request_form: datastructures.MultiDict
) -> response.Response | None:
    del_form = await DeleteTokenForm.create_form(data=request_form)
    if await del_form.validate_on_submit():
        token_id_val = int(str(del_form.token_id.data))
        await _delete_token(session.uid, token_id_val)
        await quart.flash("Token deleted successfully", "success")
        return await session.redirect(tokens)

    await quart.flash("Invalid delete request", "error")
    return None


async def _handle_issue_jwt_post(
    session: route.CommitterSession, request_form: datastructures.MultiDict
) -> response.Response | None:
    issue_form = await IssueJWTForm.create_form(data=request_form)
    if await issue_form.validate_on_submit():
        jwt_token = jwtoken.issue(session.uid)
        success_msg = htm.div[
            htm.p[
                htm.strong["Your new JWT"],
                " is:",
            ],
            htm.p[htm.code(".bg-light.border.rounded.px-1.atr-word-wrap")[jwt_token],],
        ]
        await quart.flash(_as_markup(success_msg), "success")
        return await session.redirect(tokens)

    return None
