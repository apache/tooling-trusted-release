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
import wtforms
from htpy import (
    div,
    h1,
    h2,
    h3,
    p,
    script,
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
    # TODO: Validate that at least one field is set
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
    message_glob = forms.optional("Message pattern")
    submit = forms.submit("Add ignore")


class DeleteIgnoreForm(forms.Typed):
    id = forms.hidden()
    submit = forms.submit("Delete")


class UpdateIgnoreForm(forms.Typed):
    # TODO: Validate that at least one field is set
    id = forms.hidden()
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
    message_glob = forms.optional("Message pattern")
    submit = forms.submit("Update ignore")


@routes.committer("/ignores/<committee_name>", methods=["GET", "POST"])
async def ignores(session: routes.CommitterSession, committee_name: str) -> str | response.Response:
    async with storage.read() as read:
        ragp = read.as_general_public()
        ignores = await ragp.checks.ignores(committee_name)

    content = div[
        h1["Ignored checks"],
        p[f"Manage ignored checks for committee {committee_name}."],
        _add_ignore(committee_name),
        _existing_ignores(ignores),
        _script_dom_loaded(_UPDATE_IGNORE_FORM),
    ]

    return await template.blank("Ignored checks", content)


@routes.committer("/ignores/<committee_name>/add", methods=["POST"])
async def ignores_committee_add(session: routes.CommitterSession, committee_name: str) -> str | response.Response:
    data = await quart.request.form
    form = await AddIgnoreForm.create_form(data=data)
    if not (await form.validate_on_submit()):
        return await session.redirect(ignores, error="Form validation errors")

    status = sql.CheckResultStatusIgnore.from_form_field(form.status.data)

    async with storage.write() as write:
        wacm = await write.as_committee_member(committee_name)
        await wacm.checks.ignore_add(
            release_glob=form.release_glob.data or None,
            revision_number=form.revision_number.data or None,
            checker_glob=form.checker_glob.data or None,
            primary_rel_path_glob=form.primary_rel_path_glob.data or None,
            member_rel_path_glob=form.member_rel_path_glob.data or None,
            status=status,
            message_glob=form.message_glob.data or None,
        )

    return await session.redirect(
        ignores,
        committee_name=committee_name,
        success="Ignore added",
    )


@routes.committer("/ignores/<committee_name>/delete", methods=["POST"])
async def ignores_committee_delete(session: routes.CommitterSession, committee_name: str) -> str | response.Response:
    data = await quart.request.form
    form = await DeleteIgnoreForm.create_form(data=data)
    if not (await form.validate_on_submit()):
        return await session.redirect(
            ignores,
            committee_name=committee_name,
            error="Form validation errors",
        )

    if not isinstance(form.id.data, str):
        return await session.redirect(
            ignores,
            committee_name=committee_name,
            error="Invalid ignore ID",
        )

    cri_id = int(form.id.data)
    async with storage.write() as write:
        wacm = await write.as_committee_member(committee_name)
        await wacm.checks.ignore_delete(id=cri_id)

    return await session.redirect(
        ignores,
        committee_name=committee_name,
        success="Ignore deleted",
    )


@routes.committer("/ignores/<committee_name>/update", methods=["POST"])
async def ignores_committee_update(session: routes.CommitterSession, committee_name: str) -> str | response.Response:
    data = await quart.request.form
    form = await UpdateIgnoreForm.create_form(data=data)
    if not (await form.validate_on_submit()):
        return await session.redirect(ignores, error="Form validation errors")

    status = sql.CheckResultStatusIgnore.from_form_field(form.status.data)
    if not isinstance(form.id.data, str):
        return await session.redirect(
            ignores,
            committee_name=committee_name,
            error="Invalid ignore ID",
        )
    cri_id = int(form.id.data)

    async with storage.write() as write:
        wacm = await write.as_committee_member(committee_name)
        await wacm.checks.ignore_update(
            id=cri_id,
            release_glob=form.release_glob.data or None,
            revision_number=form.revision_number.data or None,
            checker_glob=form.checker_glob.data or None,
            primary_rel_path_glob=form.primary_rel_path_glob.data or None,
            member_rel_path_glob=form.member_rel_path_glob.data or None,
            status=status,
            message_glob=form.message_glob.data or None,
        )

    return await session.redirect(
        ignores,
        committee_name=committee_name,
        success="Ignore updated",
    )


def _check_result_ignore_card(cri: sql.CheckResultIgnore) -> htpy.Element:
    h3_id = cri.id or ""
    h3_asf_uid = cri.asf_uid
    h3_created = util.format_datetime(cri.created)
    card_header_h3 = h3(".mt-3.mb-0")[f"{h3_id} - {h3_asf_uid} - {h3_created}"]

    form_update = UpdateIgnoreForm(id=cri.id)

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

    form_path_update = util.as_url(ignores_committee_update, committee_name=cri.committee_name)
    form_update_html = forms.render_table(form_update, form_path_update)

    form_delete = DeleteIgnoreForm(id=cri.id)
    form_path_delete = util.as_url(ignores_committee_delete, committee_name=cri.committee_name)
    form_delete_html = forms.render_simple(
        form_delete,
        form_path_delete,
        form_classes=".mt-2.mb-0",
        submit_classes="btn-danger",
    )

    card = div(".card.mb-5")[
        div(".card-header.d-flex.justify-content-between")[card_header_h3, form_delete_html],
        div(".card-body")[form_update_html],
    ]

    return card


def _add_ignore(committee_name: str) -> htpy.Element:
    form_path = util.as_url(ignores_committee_add, committee_name=committee_name)
    return div[
        h2["Add ignore"],
        p["Add a new ignore for a check result."],
        forms.render_columns(AddIgnoreForm(), form_path),
    ]


def _existing_ignores(ignores: list[sql.CheckResultIgnore]) -> htpy.Element:
    return div[
        h2["Existing ignores"],
        [_check_result_ignore_card(cri) for cri in ignores] or p["No ignores found."],
    ]


def _script_dom_loaded(text: str) -> htpy.Element:
    script_text = markupsafe.Markup(f"""
document.addEventListener("DOMContentLoaded", function () {{
{text}
}});
""")
    return script[script_text]
