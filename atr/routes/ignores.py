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

from typing import Final

import htpy
import markupsafe
import quart
import werkzeug.wrappers.response as response
from htpy import (
    button,
    div,
    h1,
    h2,
    h3,
    input,
    p,
    script,
    table,
    td,
    th,
    tr,
)

import atr.forms as forms
import atr.models.sql as sql
import atr.routes as routes
import atr.storage as storage
import atr.template as template
import atr.util as util

# TODO: Port to TypeScript and move to static files
_UPDATE_IGNORE_FORM: Final[str] = """
document.querySelectorAll("table.page-details input.form-control").forEach(function (input) {
    var row = input.closest("tr");
    var updateBtn = row.querySelector("button.btn-primary");
    function check() {
        if (input.value !== input.dataset.value) {
            updateBtn.classList.remove("disabled");
        } else {
            updateBtn.classList.add("disabled");
        }
    }
    input.addEventListener("input", check);
    check();
});
"""


class AddIgnoreForm(forms.Typed):
    release_glob = forms.optional("Release pattern")
    revision_number = forms.optional("Revision number (literal)")
    checker_glob = forms.optional("Checker pattern")
    primary_rel_path_glob = forms.optional("Primary rel path pattern")
    member_rel_path_glob = forms.optional("Member rel path pattern")
    status = forms.select(
        "Status",
        optional=True,
        choices=[
            (None, "-"),
            (sql.CheckResultStatusIgnore.EXCEPTION, "Exception"),
            (sql.CheckResultStatusIgnore.FAILURE, "Failure"),
            (sql.CheckResultStatusIgnore.WARNING, "Warning"),
        ],
    )
    message = forms.optional("Message pattern")
    submit = forms.submit("Add ignore")

    # TODO: Validate that at least one field is set


@routes.committer("/ignores/<committee_name>", methods=["GET", "POST"])
async def ignores(session: routes.CommitterSession, committee_name: str) -> str | response.Response:
    async with storage.read(session.asf_uid) as read:
        ragp = read.as_general_public()
        ignores = await ragp.checks.ignores(committee_name)

    content = div[
        h1["Ignored checks"],
        p[f"Manage ignored checks for committee {committee_name}."],
        _add_ignore(committee_name),
        _existing_ignores(ignores),
        _script(_UPDATE_IGNORE_FORM),
    ]

    return await template.blank("Ignored checks", content)


@routes.committer("/ignores/<committee_name>/add", methods=["POST"])
async def ignores_committee_add(session: routes.CommitterSession, committee_name: str) -> str | response.Response:
    data = await quart.request.form
    form = await AddIgnoreForm.create_form(data=data)
    if not (await form.validate_on_submit()):
        return await session.redirect(ignores, error="Form validation errors")

    status = sql.CheckResultStatusIgnore.from_form_field(form.status.data)

    async with storage.write(session.asf_uid) as write:
        wacm = write.as_committee_member(committee_name)
        await wacm.checks.ignore_add(
            release_glob=form.release_glob.data,
            revision_number=form.revision_number.data,
            checker_glob=form.checker_glob.data,
            primary_rel_path_glob=form.primary_rel_path_glob.data,
            member_rel_path_glob=form.member_rel_path_glob.data,
            status=status,
            message_glob=form.message.data,
        )

    return await session.redirect(
        ignores,
        committee_name=committee_name,
        success="Ignore added",
    )


def _check_result_ignore_card(cri: sql.CheckResultIgnore) -> htpy.Element:
    card_header_h3 = h3(".mb-0")[f"{cri.id or ''} - {cri.asf_uid} - {util.format_datetime(cri.created)}"]

    table_rows = []

    def add_row(label: str, value: str | None) -> None:
        nonlocal table_rows
        if value is not None:
            table_rows.append(
                tr[
                    th[label],
                    td[input(".form-control.form-control-sm", data_value=value, value=value)],
                    td[
                        button(".btn.btn-primary.btn-sm.me-4.disabled")["Update"],
                        button(".btn.btn-danger.btn-sm")["Delete"],
                    ],
                ]
            )

    add_row("Release", cri.release_glob)
    add_row("Revision number (literal)", cri.revision_number)
    add_row("Checker", cri.checker_glob)
    add_row("Primary path", cri.primary_rel_path_glob)
    add_row("Member path", cri.member_rel_path_glob)
    add_row("Status (enum)", cri.status.value.title() if cri.status else "")
    add_row("Message", cri.message_glob)

    table_striped = table(".table.table-striped.table-bordered.page-details")[table_rows]

    card = div(".card")[
        div(".card-header")[card_header_h3],
        div(".card-body")[table_striped, p[button(".btn.btn-danger.btn-sm")["Delete"]]],
    ]

    return card


def _add_ignore(committee_name: str) -> htpy.Element:
    form_path = util.as_url(ignores_committee_add, committee_name=committee_name)
    return div[
        h2["Add ignore"],
        p["Add a new ignore for a check result."],
        forms.render(AddIgnoreForm(), form_path),
    ]


def _existing_ignores(ignores: list[sql.CheckResultIgnore]) -> htpy.Element:
    return div[
        h2["Existing ignores"],
        [_check_result_ignore_card(cri) for cri in ignores],
    ]


def _script(text: str) -> htpy.Element:
    return script[
        markupsafe.Markup(f"""
document.addEventListener("DOMContentLoaded", function () {{
  {text}
}});
""")
    ]
