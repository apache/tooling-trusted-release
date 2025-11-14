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

"""keys.py"""

from typing import Annotated, Literal

import htpy
import markupsafe
import pydantic

import atr.form as form
import atr.htm as htm
import atr.shared as shared
import atr.storage as storage
import atr.storage.types as types
import atr.template as template
import atr.util as util

type DELETE_OPENPGP_KEY = Literal["delete_openpgp_key"]
type DELETE_SSH_KEY = Literal["delete_ssh_key"]
type UPDATE_COMMITTEE_KEYS = Literal["update_committee_keys"]


class AddOpenPGPKeyForm(form.Form):
    public_key: str = form.label(
        "Public OpenPGP key",
        'Your public key should be in ASCII-armored format, starting with "-----BEGIN PGP PUBLIC KEY BLOCK-----"',
        widget=form.Widget.TEXTAREA,
    )
    selected_committees: form.StrList = form.label(
        "Associate key with committees",
        "Select the committees with which to associate your key.",
    )

    @pydantic.model_validator(mode="after")
    def validate_at_least_one_committee(self) -> "AddOpenPGPKeyForm":
        if not self.selected_committees:
            raise ValueError("You must select at least one committee to associate with this key")
        return self


class AddSSHKeyForm(form.Form):
    key: str = form.label(
        "SSH public key",
        "Your SSH public key should be in the standard format, starting with a key type"
        ' (like "ssh-rsa" or "ssh-ed25519") followed by the key data.',
        widget=form.Widget.TEXTAREA,
    )


class DeleteOpenPGPKeyForm(form.Form):
    variant: DELETE_OPENPGP_KEY = form.value(DELETE_OPENPGP_KEY)
    fingerprint: str = form.label("Fingerprint", widget=form.Widget.HIDDEN)


class DeleteSSHKeyForm(form.Form):
    variant: DELETE_SSH_KEY = form.value(DELETE_SSH_KEY)
    fingerprint: str = form.label("Fingerprint", widget=form.Widget.HIDDEN)


class UpdateCommitteeKeysForm(form.Empty):
    variant: UPDATE_COMMITTEE_KEYS = form.value(UPDATE_COMMITTEE_KEYS)
    committee_name: str = form.label("Committee name", widget=form.Widget.HIDDEN)


type KeysForm = Annotated[
    DeleteOpenPGPKeyForm | DeleteSSHKeyForm | UpdateCommitteeKeysForm,
    form.DISCRIMINATOR,
]


class UpdateKeyCommitteesForm(form.Form):
    selected_committees: form.StrList = form.label(
        "Associated PMCs",
        widget=form.Widget.CUSTOM,
    )


class UploadKeysForm(form.Form):
    key: form.File = form.label(
        "KEYS file",
        "Upload a KEYS file containing multiple PGP public keys."
        " The file should contain keys in ASCII-armored format, starting with"
        ' "-----BEGIN PGP PUBLIC KEY BLOCK-----".',
        widget=form.Widget.CUSTOM,
    )
    keys_url: form.OptionalURL = form.label(
        "KEYS file URL",
        "Enter a URL to a KEYS file. This will be fetched by the server.",
        widget=form.Widget.CUSTOM,
    )
    selected_committee: str = form.label(
        "Associate keys with committee",
        "Select the committee with which to associate these keys.",
        widget=form.Widget.RADIO,
    )

    @pydantic.model_validator(mode="after")
    def validate_key_source(self) -> "UploadKeysForm":
        if (not self.key) and (not self.keys_url):
            raise ValueError("Either a file or a URL is required")
        if self.key and self.keys_url:
            raise ValueError("Provide either a file or a URL, not both")
        return self


def _get_results_table_css() -> htm.Element:
    return htm.style[
        markupsafe.Markup(
            """
        .page-rotated-header {
            height: 180px;
            position: relative;
            vertical-align: bottom;
            padding-bottom: 5px;
            width: 40px;
        }
        .page-rotated-header > div {
            transform-origin: bottom left;
            transform: translateX(25px) rotate(-90deg);
            position: absolute;
            bottom: 12px;
            left: 6px;
            white-space: nowrap;
            text-align: left;
        }
        .table th, .table td {
            text-align: center;
            vertical-align: middle;
        }
        .table td.page-key-details {
            text-align: left;
            font-family: ui-monospace, "SFMono-Regular", "Menlo", "Monaco", "Consolas", monospace;
            font-size: 0.9em;
            word-break: break-all;
        }
        .page-status-cell-new {
            background-color: #197a4e !important;
        }
        .page-status-cell-existing {
            background-color: #868686 !important;
        }
        .page-status-cell-unknown {
            background-color: #ffecb5 !important;
        }
        .page-status-cell-error {
            background-color: #dc3545 !important;
        }
        .page-status-square {
            display: inline-block;
            width: 36px;
            height: 36px;
            vertical-align: middle;
        }
        .page-table-bordered th, .page-table-bordered td {
            border: 1px solid #dee2e6;
        }
        tbody tr {
            height: 40px;
        }
        """
        )
    ]


def _render_results_table(
    page: htm.Block, results: storage.outcome.List, submitted_committees: list[str], committee_map: dict[str, str]
) -> None:
    """Render the KEYS processing results table."""
    page.h2["KEYS processing results"]
    page.p[
        "The following keys were found in your KEYS file and processed against the selected committees. "
        "Green squares indicate that a key was added, grey squares indicate that a key already existed, "
        "and red squares indicate an error."
    ]

    thead = htm.Block(htm.thead)
    header_row = htm.Block(htm.tr)
    header_row.th(scope="col")["Key ID"]
    header_row.th(scope="col")["User ID"]
    for committee_name in submitted_committees:
        header_row.th(".page-rotated-header", scope="col")[htm.div[committee_map.get(committee_name, committee_name)]]
    thead.append(header_row.collect())

    tbody = htm.Block(htm.tbody)
    for outcome in results.outcomes():
        if outcome.ok:
            key_obj = outcome.result_or_none()
            fingerprint = key_obj.key_model.fingerprint if key_obj else "UNKNOWN"
            email_addr = key_obj.key_model.primary_declared_uid if key_obj else ""
            # Check whether the LINKED flag is set
            added_flag = bool(key_obj.status & types.KeyStatus.LINKED) if key_obj else False
            error_flag = False
        else:
            err = outcome.error_or_none()
            key_obj = getattr(err, "key", None) if err else None
            fingerprint = key_obj.key_model.fingerprint if key_obj else "UNKNOWN"
            email_addr = key_obj.key_model.primary_declared_uid if key_obj else ""
            added_flag = False
            error_flag = True

        row = htm.Block(htm.tr)
        row.td(".page-key-details.px-2")[htm.code[fingerprint[-16:].upper()]]
        row.td(".page-key-details.px-2")[email_addr or ""]

        for committee_name in submitted_committees:
            if error_flag:
                cell_class = "page-status-cell-error"
                title_text = "Error processing key"
            elif added_flag:
                cell_class = "page-status-cell-new"
                title_text = "Newly linked"
            else:
                cell_class = "page-status-cell-existing"
                title_text = "Already linked"

            row.td(".text-center.align-middle.page-status-cell-container")[
                htm.span(f".page-status-square.{cell_class}", title=title_text)
            ]

        tbody.append(row.collect())

    table_div = htm.div(".table-responsive")[
        htm.table(".table.table-striped.page-table-bordered.table-sm.mt-3")[thead.collect(), tbody.collect()]
    ]
    page.append(table_div)

    processing_errors = [o for o in results.outcomes() if not o.ok]
    if processing_errors:
        page.h3(".text-danger.mt-4")["Processing errors"]
        for outcome in processing_errors:
            err = outcome.error_or_none()
            page.div(".alert.alert-danger.p-2.mb-3")[str(err)]


async def render_upload_page(
    results: storage.outcome.List | None = None,
    submitted_committees: list[str] | None = None,
    error: bool = False,
) -> str:
    """Render the upload page with optional results."""
    import atr.get as get
    import atr.post as post

    async with storage.write() as write:
        participant_of_committees = await write.participant_of_committees()

    eligible_committees = [
        c for c in participant_of_committees if (not util.committee_is_standing(c.name)) or (c.name == "tooling")
    ]

    committee_choices = [(c.name, c.display_name) for c in eligible_committees]
    committee_map = {c.name: c.display_name for c in eligible_committees}

    page = htm.Block()
    page.p[htm.a(".atr-back-link", href=util.as_url(get.keys.keys))["← Back to Manage keys"]]
    page.h1["Upload a KEYS file"]
    page.p["Upload a KEYS file containing multiple OpenPGP public signing keys."]

    if results and submitted_committees:
        page.append(_get_results_table_css())
        _render_results_table(page, results, submitted_committees, committee_map)

    custom_tabs_widget = _render_upload_tabs()

    form.render_block(
        page,
        model_cls=shared.keys.UploadKeysForm,
        action=util.as_url(post.keys.upload),
        submit_label="Upload KEYS file",
        cancel_url=util.as_url(get.keys.keys),
        defaults={"selected_committee": committee_choices},
        custom={"key": custom_tabs_widget},
        skip=["keys_url"],
        border=True,
        wider_widgets=True,
    )

    return await template.blank(
        "Upload a KEYS file",
        content=page.collect(),
        description="Upload a KEYS file containing multiple OpenPGP public signing keys.",
    )


def _render_upload_tabs() -> htm.Element:
    """Render the tabbed interface for file upload or URL input."""
    tabs_ul = htm.ul(".nav.nav-tabs", id="keysUploadTab", role="tablist")[
        htm.li(".nav-item", role="presentation")[
            htpy.button(
                class_="nav-link active",
                id="file-upload-tab",
                data_bs_toggle="tab",
                data_bs_target="#file-upload-pane",
                type="button",
                role="tab",
                aria_controls="file-upload-pane",
                aria_selected="true",
            )["Upload from file"]
        ],
        htm.li(".nav-item", role="presentation")[
            htpy.button(
                class_="nav-link",
                id="url-upload-tab",
                data_bs_toggle="tab",
                data_bs_target="#url-upload-pane",
                type="button",
                role="tab",
                aria_controls="url-upload-pane",
                aria_selected="false",
            )["Upload from URL"]
        ],
    ]

    file_pane = htm.div(".tab-pane.fade.show.active", id="file-upload-pane", role="tabpanel")[
        htm.div(".pt-3")[
            htpy.input(class_="form-control", id="key", name="key", type="file"),
            htm.div(".form-text.text-muted.mt-2")[
                "Upload a KEYS file containing multiple PGP public keys. The file should contain keys in "
                'ASCII-armored format, starting with "-----BEGIN PGP PUBLIC KEY BLOCK-----".'
            ],
        ]
    ]

    url_pane = htm.div(".tab-pane.fade", id="url-upload-pane", role="tabpanel")[
        htm.div(".pt-3")[
            htpy.input(
                class_="form-control",
                id="keys_url",
                name="keys_url",
                placeholder="Enter URL to KEYS file",
                type="url",
                value="",
            ),
            htm.div(".form-text.text-muted.mt-2")["Enter a URL to a KEYS file. This will be fetched by the server."],
        ]
    ]

    tab_content = htm.div(".tab-content", id="keysUploadTabContent")[file_pane, url_pane]

    return htm.div[tabs_ul, tab_content]
