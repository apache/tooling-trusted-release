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
import logging
import secrets
import time
from typing import Final

import markupsafe
import quart
import sqlmodel
import werkzeug.datastructures as datastructures
import werkzeug.wrappers.response as response
import wtforms
import wtforms.fields.core as core
from htpy import Element, code, div, form, h1, h2, p, strong, table, tbody, td, th, thead, tr

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.template as templates
import atr.util as util

_EXPIRY_DAYS: Final[int] = 180
_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

type Fragment = Element | core.Field | str


class AddTokenForm(util.QuartFormTyped):
    csrf_token: wtforms.Field
    label = wtforms.StringField(
        "Label",
        validators=[wtforms.validators.Optional(), wtforms.validators.Length(max=100)],
        render_kw={"placeholder": "E.g. CI bot"},
    )
    submit = wtforms.SubmitField("Generate token")


class DeleteTokenForm(util.QuartFormTyped):
    csrf_token: wtforms.Field
    token_id = wtforms.HiddenField(validators=[wtforms.validators.InputRequired()])
    submit = wtforms.SubmitField("Delete")


@routes.committer("/tokens", methods=["GET", "POST"])
async def tokens(session: routes.CommitterSession) -> str | response.Response:
    request_form = await quart.request.form

    if is_post := quart.request.method == "POST":
        maybe_response = await _handle_post(session, request_form)
        if maybe_response is not None:
            return maybe_response

    add_form = await AddTokenForm.create_form(data=request_form if is_post else None)

    start = time.perf_counter_ns()
    tokens_list = await _fetch_tokens(session.uid)
    end = time.perf_counter_ns()
    _LOGGER.info("Tokens list fetched in %dms", (end - start) / 1_000_000)

    start = time.perf_counter_ns()
    add_form_elem = _build_add_form_element(add_form)
    tokens_table = _build_tokens_table(tokens_list)

    content_elem = div[
        h1["Tokens"],
        h2["Personal Access Tokens (PATs)"],
        p[
            "Generate tokens for API access. For security, the plaintext token "
            "is shown only once when you create it. You can revoke tokens you no "
            "longer need.",
        ],
        div(".card.mb-4")[
            div(".card-header")["Generate new token"],
            div(".card-body")[add_form_elem],
        ],
        tokens_table,
    ]
    end = time.perf_counter_ns()
    _LOGGER.info("Content elem built in %dms", (end - start) / 1_000_000)

    start = time.perf_counter_ns()
    rendered = await templates.render(
        "blank.html",
        title="Tokens",
        description="Manage your Personal Access Tokens.",
        content=content_elem,
    )
    end = time.perf_counter_ns()
    _LOGGER.info("Rendered in %dms", (end - start) / 1_000_000)

    return rendered


def _as_markup(fragment: Fragment) -> markupsafe.Markup:
    return markupsafe.Markup(str(fragment))


def _build_add_form_element(a_form: AddTokenForm) -> markupsafe.Markup:
    elem = form(method="post", action=util.as_url(tokens))[
        _as_markup(a_form.csrf_token),
        div(".mb-3")[
            a_form.label.label,
            a_form.label(class_="form-control"),
        ],
        a_form.submit(class_="btn btn-primary"),
    ]
    return _as_markup(elem)


def _build_delete_form_element(token_id: int | None) -> markupsafe.Markup:
    d_form = DeleteTokenForm()
    d_form.token_id.data = "" if token_id is None else str(token_id)
    elem = form(".mb-0", method="post", action=util.as_url(tokens))[
        _as_markup(d_form.csrf_token),
        _as_markup(d_form.token_id),
        d_form.submit(class_="btn btn-sm btn-danger"),
    ]
    return _as_markup(elem)


def _build_tokens_table(tokens_list: list[models.PersonalAccessToken]) -> markupsafe.Markup:
    if not tokens_list:
        return _as_markup(p["No tokens found."])

    rows = [
        tr(".align-middle")[
            td[t.label or ""],
            td[util.format_datetime(t.created)],
            td[util.format_datetime(t.expires)],
            td[util.format_datetime(t.last_used) if t.last_used else "Never"],
            td[_build_delete_form_element(t.id)],
        ]
        for t in tokens_list
    ]

    table_elem = table(".table.table-striped")[
        thead[
            tr[
                th["Label"],
                th["Created"],
                th["Expires"],
                th["Last used"],
                th[""],
            ]
        ],
        tbody[rows],
    ]
    return _as_markup(table_elem)


async def _create_token(uid: str, label: str | None) -> str:
    plaintext = secrets.token_urlsafe(32)
    token_hash = hashlib.sha3_256(plaintext.encode()).hexdigest()
    created = datetime.datetime.now(datetime.UTC)
    expires = created + datetime.timedelta(days=_EXPIRY_DAYS)

    async with db.session() as data:
        async with data.begin():
            pat = models.PersonalAccessToken(
                asfuid=uid,
                token_hash=token_hash,
                created=created,
                expires=expires,
                label=label,
            )
            data.add(pat)
    return plaintext


@db.session_commit_function
async def _delete_token(data: db.Session, uid: str, token_id: int) -> None:
    pat = await data.query_one_or_none(
        sqlmodel.select(models.PersonalAccessToken).where(
            models.PersonalAccessToken.id == token_id,
            models.PersonalAccessToken.asfuid == uid,
        )
    )
    if pat:
        await data.delete(pat)


@db.session_function
async def _fetch_tokens(data: db.Session, uid: str) -> list[models.PersonalAccessToken]:
    via = models.validate_instrumented_attribute
    stmt = (
        sqlmodel.select(models.PersonalAccessToken)
        .where(models.PersonalAccessToken.asfuid == uid)
        .order_by(via(models.PersonalAccessToken.created))
    )
    return await data.query_all(stmt)


async def _handle_post(
    session: routes.CommitterSession, request_form: datastructures.MultiDict
) -> response.Response | None:
    if "token_id" in request_form:
        del_form = await DeleteTokenForm.create_form(data=request_form)
        if await del_form.validate_on_submit():
            token_id_val = int(str(del_form.token_id.data))
            await _delete_token(session.uid, token_id_val)
            await quart.flash("Token deleted successfully", "success")
            return await session.redirect(tokens)
        await quart.flash("Invalid delete request", "error")
        return None

    add_form = await AddTokenForm.create_form(data=request_form)
    if await add_form.validate_on_submit():
        label_val = str(add_form.label.data) if add_form.label.data else None
        plaintext = await _create_token(session.uid, label_val)
        success_msg = div[
            p[
                strong["Your new token"],
                " is ",
                code(".bg-light.border.rounded.px-1")[plaintext],
            ],
            p(".mb-0")["Copy it now as you will not be able to see it again."],
        ]
        await quart.flash(_as_markup(success_msg), "success")
        return await session.redirect(tokens)

    return None
