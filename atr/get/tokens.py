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

import atr.blueprints.get as get
import atr.form as form
import atr.htm as htm
import atr.models.sql as sql
import atr.post as post
import atr.shared as shared
import atr.storage as storage
import atr.template as template
import atr.util as util
import atr.web as web


@get.committer("/tokens")
async def tokens(session: web.Committer) -> str:
    async with storage.read_as_foundation_committer() as rafc:
        tokens_list = await rafc.tokens.own_personal_access_tokens()
        most_recent_pat = await rafc.tokens.most_recent_jwt_pat()

    page = htm.Block()
    page.h1["Tokens"]
    page.h2["Personal Access Tokens (PATs)"]
    page.p[
        """Generate tokens for API access. For security, the plaintext
        token is shown only once when you create it. You can revoke tokens
        you no longer need."""
    ]
    add_form = form.render(
        model_cls=shared.tokens.AddTokenForm,
        form_classes=".mb-0",
        submit_label="Generate token",
    )
    page.div(".card.mb-4")[
        htm.div(".card-header")["Generate new token"],
        htm.div(".card-body")[add_form],
    ]
    _build_tokens_table(page, tokens_list)

    page.h2["JSON Web Token (JWT)"]
    jwt_section = htm.Block()
    jwt_section.p[
        """Generate a JSON Web Token (JWT) to authenticate calls to ATR's
        private API routes. Treat the token like a password and include it
        in the Authorization header as a Bearer token when invoking the
        protected endpoints."""
    ]
    form.render_block(
        jwt_section,
        model_cls=form.Empty,
        action=util.as_url(post.tokens.jwt_post),
        form_classes="#issue-jwt-form",
        submit_label="Generate JWT",
    )
    jwt_section.pre(id="jwt-output", class_="d-none mt-2 p-3 atr-word-wrap border rounded w-50")
    if most_recent_pat and most_recent_pat.last_used:
        jwt_section.p(".mt-3")[
            "You most recently used a PAT to issue a JWT at ",
            htm.strong[util.format_datetime(most_recent_pat.last_used) + "Z"],
            ", using the PAT labelled ",
            htm.code[most_recent_pat.label or "[Untitled]"],
            ".",
        ]
    page.append(jwt_section)

    return await template.render_sync(
        "blank.html",
        title="Tokens",
        description="Manage your PATs and JWTs.",
        content=page.collect(),
        javascripts=[util.static_path("js", "create-a-jwt.js")],
    )


def _build_tokens_table(page: htm.Block, tokens_list: list[sql.PersonalAccessToken]) -> None:
    if not tokens_list:
        page.p["No tokens found."]
        return

    tbody = htm.Block(htm.tbody)
    for t in tokens_list:
        if not t.id:
            continue

        delete_form = form.render(
            model_cls=shared.tokens.DeleteTokenForm,
            action=util.as_url(post.tokens.tokens),
            form_classes=".mb-0",
            submit_classes="btn-sm btn-danger",
            submit_label="Delete",
            defaults={"token_id": t.id},
            empty=True,
        )
        tbody.tr(".align-middle")[
            htm.td[t.label or ""],
            htm.td[util.format_datetime(t.created)],
            htm.td[util.format_datetime(t.expires)],
            htm.td[util.format_datetime(t.last_used) if t.last_used else "Never"],
            htm.td[delete_form],
        ]

    page.table(".table.table-striped")[
        htm.thead[
            htm.tr[
                htm.th["Label"],
                htm.th["Created"],
                htm.th["Expires"],
                htm.th["Last used"],
                htm.th[""],
            ]
        ],
        tbody.collect(),
    ]
