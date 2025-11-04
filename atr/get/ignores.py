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

import markupsafe
import wtforms

import atr.blueprints.get as get
import atr.forms as forms
import atr.htm as htm
import atr.models.sql as sql
import atr.post as post
import atr.shared as shared
import atr.storage as storage
import atr.template as template
import atr.util as util
import atr.web as web

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


@get.committer("/ignores/<committee_name>")
async def ignores(session: web.Committer, committee_name: str) -> str | web.WerkzeugResponse:
    async with storage.read() as read:
        ragp = read.as_general_public()
        ignores = await ragp.checks.ignores(committee_name)

    content = htm.div[
        htm.h1["Ignored checks"],
        htm.p[f"Manage ignored checks for committee {committee_name}."],
        _add_ignore(committee_name),
        _existing_ignores(ignores),
        _script_dom_loaded(_UPDATE_IGNORE_FORM),
    ]

    return await template.blank("Ignored checks", content)


def _check_result_ignore_card(cri: sql.CheckResultIgnore) -> htm.Element:
    h3_id = cri.id or ""
    h3_asf_uid = cri.asf_uid
    h3_created = util.format_datetime(cri.created)
    card_header_h3 = htm.h3(".mt-3.mb-0")[f"{h3_id} - {h3_asf_uid} - {h3_created}"]

    form_update = shared.ignores.UpdateIgnoreForm(id=cri.id)

    def set_field(field: wtforms.StringField | wtforms.SelectField, value: str | None) -> None:
        if value is not None:
            field.data = value

    set_field(form_update.release_glob, cri.release_glob)
    set_field(form_update.revision_number, cri.revision_number)
    set_field(form_update.checker_glob, cri.checker_glob)
    set_field(form_update.primary_rel_path_glob, cri.primary_rel_path_glob)
    set_field(form_update.member_rel_path_glob, cri.member_rel_path_glob)
    set_field(form_update.status, cri.status.to_form_field() if cri.status else "None")
    set_field(form_update.message_glob, cri.message_glob)

    form_path_update = util.as_url(post.ignores.ignores_committee_update, committee_name=cri.committee_name)
    form_update_html = forms.render_table(form_update, form_path_update)

    form_delete = shared.ignores.DeleteIgnoreForm(id=cri.id)
    form_path_delete = util.as_url(post.ignores.ignores_committee_delete, committee_name=cri.committee_name)
    form_delete_html = forms.render_simple(
        form_delete,
        form_path_delete,
        form_classes=".mt-2.mb-0",
        submit_classes="btn-danger",
    )

    card = htm.div(".card.mb-5")[
        htm.div(".card-header.d-flex.justify-content-between")[card_header_h3, form_delete_html],
        htm.div(".card-body")[form_update_html],
    ]

    return card


def _add_ignore(committee_name: str) -> htm.Element:
    form_path = util.as_url(post.ignores.ignores_committee_add, committee_name=committee_name)
    return htm.div[
        htm.h2["Add ignore"],
        htm.p["Add a new ignore for a check result."],
        forms.render_columns(shared.ignores.AddIgnoreForm(), form_path),
    ]


def _existing_ignores(ignores: list[sql.CheckResultIgnore]) -> htm.Element:
    return htm.div[
        htm.h2["Existing ignores"],
        [_check_result_ignore_card(cri) for cri in ignores] or htm.p["No ignores found."],
    ]


def _script_dom_loaded(text: str) -> htm.Element:
    script_text = markupsafe.Markup(f"""
document.addEventListener("DOMContentLoaded", function () {{
{text}
}});
""")
    return htm.script[script_text]
