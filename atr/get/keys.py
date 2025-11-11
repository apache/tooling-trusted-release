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


import markupsafe

import atr.blueprints.get as get
import atr.db as db
import atr.form as form
import atr.htm as htm
import atr.models.sql as sql
import atr.post as post
import atr.shared as shared
import atr.storage as storage
import atr.template as template
import atr.util as util
import atr.web as web


@get.committer("/keys/add")
async def add(session: web.Committer) -> str:
    """Add a new public signing key to the user's account."""
    async with storage.write() as write:
        participant_of_committees = await write.participant_of_committees()

    committee_choices = [(c.name, c.display_name or c.name) for c in participant_of_committees]

    page = htm.Block()
    page.p[htm.a(".atr-back-link", href=util.as_url(keys))["← Back to Manage keys"],]
    page.div(".my-4")[
        htm.h1(".mb-4")["Add your OpenPGP key"],
        htm.p["Add your public key to use for signing release artifacts."],
    ]
    form.render_block(
        page,
        model_cls=shared.keys.AddOpenPGPKeyForm,
        action=util.as_url(post.keys.add),
        submit_label="Add OpenPGP key",
        cancel_url=util.as_url(keys),
        defaults={
            "selected_committees": committee_choices,
        },
    )

    page.append(
        htm.script[
            markupsafe.Markup("""
            document.addEventListener("DOMContentLoaded", function() {
                const checkboxes = document.querySelectorAll("input[name='selected_committees']");
                if (checkboxes.length === 0) return;

                const firstCheckbox = checkboxes[0];
                const container = firstCheckbox.closest(".col-sm-8");
                if (!container) return;

                const button = document.createElement("button");
                button.id = "toggleCommitteesBtn";
                button.type = "button";
                button.className = "btn btn-outline-secondary btn-sm mt-2";
                button.textContent = "Select all committees";

                button.addEventListener("click", function() {
                    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
                    checkboxes.forEach(cb => cb.checked = !allChecked);
                    button.textContent = allChecked ? "Select all committees" : "Deselect all committees";
                });

                container.appendChild(button);
            });
            """)
        ]
    )

    return await template.blank(
        "Add your OpenPGP key",
        content=page.collect(),
        description="Add your public signing key to your ATR account.",
    )


@get.committer("/keys/details/<fingerprint>")
async def details(session: web.Committer, fingerprint: str) -> str | web.WerkzeugResponse:
    """Display details for a specific OpenPGP key."""
    return await shared.keys.details(session, fingerprint)


@get.committer("/keys/export/<committee_name>")
async def export(session: web.Committer, committee_name: str) -> web.TextResponse:
    """Export a KEYS file for a specific committee."""
    async with storage.write() as write:
        wafc = write.as_foundation_committer()
        keys_file_text = await wafc.keys.keys_file_text(committee_name)

    return web.TextResponse(keys_file_text)


@get.committer("/keys")
async def keys(session: web.Committer) -> str:
    """View all keys associated with the user's account."""
    committees_to_query = list(set(session.committees + session.projects))

    async with db.session() as data:
        user_keys = await data.public_signing_key(apache_uid=session.uid.lower(), _committees=True).all()
        user_ssh_keys = await data.ssh_key(asf_uid=session.uid).all()
        user_committees_with_keys = await data.committee(name_in=committees_to_query, _public_signing_keys=True).all()
    for key in user_keys:
        key.committees.sort(key=lambda c: c.name)

    page = htm.Block()
    page.h1["Manage keys"]
    page.p(".mb-4")[
        htm.a(".btn.btn-sm.btn-secondary.me-3", href="#your-public-keys")["Your public keys"],
        htm.a(".btn.btn-sm.btn-secondary", href="#your-committee-keys")["Your committee's keys"],
    ]

    page.h2("#your-public-keys")["Your public keys"]
    page.p["Review your public keys used for signing release artifacts."]
    page.div(".d-flex.gap-3.mb-4")[
        htm.a(".btn.btn-outline-primary", href=util.as_url(add))["Add your OpenPGP key"],
        htm.a(".btn.btn-outline-primary", href=util.as_url(ssh_add))["Add your SSH key"],
    ]

    _openpgp_keys(page, list(user_keys))
    _ssh_keys(page, list(user_ssh_keys))
    _committee_keys(page, list(user_committees_with_keys))

    return await template.blank(
        "Manage keys",
        content=page.collect(),
        description="Review your keys.",
    )


@get.committer("/keys/ssh/add")
async def ssh_add(session: web.Committer) -> str:
    """Add a new SSH key to the user's account."""
    page = htm.Block()
    page.p[htm.a(".atr-back-link", href=util.as_url(keys))["← Back to Manage keys"]]
    page.h1["Add your SSH key"]
    page.p["Add your SSH public key to use for rsync authentication."]
    page.div[
        htm.p[
            "Welcome, ",
            htm.strong[session.uid],
            "! You are authenticated as an ASF committer.",
        ]
    ]

    form.render_block(
        page,
        model_cls=shared.keys.AddSSHKeyForm,
        action=util.as_url(post.keys.ssh_add),
        submit_label="Add SSH key",
    )

    return await template.blank(
        "Add your SSH key",
        content=page.collect(),
        description="Add your SSH public key to your account.",
    )


@get.committer("/keys/upload")
async def upload(session: web.Committer) -> str:
    """Upload a KEYS file containing multiple OpenPGP keys."""
    return await shared.keys.upload(session)


def _committee_keys(page: htm.Block, user_committees_with_keys: list[sql.Committee]) -> None:
    page.h2("#your-committee-keys")["Your committee's keys"]
    page.div(".mb-4")[htm.a(".btn.btn-outline-primary", href=util.as_url(upload))["Upload a KEYS file"]]

    for committee in user_committees_with_keys:
        if not util.committee_is_standing(committee.name):
            page.h3(f"#committee-{committee.name}.mt-3")[committee.display_name or committee.name]

            if committee.public_signing_keys:
                thead = htm.thead[
                    htm.tr[
                        htm.th(".px-2", scope="col")["Key ID"],
                        htm.th(".px-2", scope="col")["Email"],
                        htm.th(".px-2", scope="col")["Apache UID"],
                    ]
                ]
                tbody = htm.Block(htm.tbody)
                for key in committee.public_signing_keys:
                    row = htm.Block(htm.tr)
                    details_url = util.as_url(details, fingerprint=key.fingerprint)
                    row.td(".text-break.font-monospace.px-2")[htm.a(href=details_url)[key.fingerprint[-16:].upper()]]
                    email = util.email_from_uid(key.primary_declared_uid) if key.primary_declared_uid else "-"
                    row.td(".text-break.px-2")[email or "-"]
                    row.td(".text-break.px-2")[key.apache_uid or "-"]
                    tbody.append(row.collect())

                page.div(".table-responsive.mb-2")[
                    htm.table(".table.border.table-striped.table-hover.table-sm")[thead, tbody.collect()]
                ]
                page.p(".text-muted")[
                    "The ",
                    htm.code["KEYS"],
                    " file is automatically generated when you add or remove a key,"
                    " but you can also use the form below to manually regenerate it.",
                ]

                form.render_block(
                    page,
                    model_cls=shared.keys.UpdateCommitteeKeysForm,
                    action=util.as_url(post.keys.keys),
                    form_classes=".mb-4.d-inline-block",
                    submit_label="Regenerate KEYS file",
                    submit_classes="btn btn-sm btn-outline-secondary",
                    defaults={"committee_name": committee.name},
                    empty=True,
                )
            else:
                page.p(".mb-4")["No keys uploaded for this committee yet."]


def _openpgp_keys(page: htm.Block, user_keys: list[sql.PublicSigningKey]) -> None:
    page.h3["Your OpenPGP keys"]
    if user_keys:
        thead = htm.thead[
            htm.tr[
                htm.th(".px-2", scope="col")["Key ID"],
                htm.th(".px-2", scope="col")["Committees"],
                htm.th(".px-2", scope="col")["Action"],
            ]
        ]

        tbody = htm.Block(htm.tbody)
        for key in user_keys:
            row = htm.Block(htm.tr, classes=".page-user-openpgp-key")
            row.td(".text-break.px-2.align-middle")[
                htm.a(href=util.as_url(details, fingerprint=key.fingerprint))[key.fingerprint[-16:].upper()]
            ]
            if key.committees:
                committee_names = ", ".join([c.name for c in key.committees])
                row.td(".text-break.px-2.align-middle")[committee_names]
            else:
                row.td(".text-break.px-2.align-middle")["No PMCs associated"]
            with row.block(htm.td, classes=".px-2") as td:
                form.render_block(
                    td,
                    model_cls=shared.keys.DeleteOpenPGPKeyForm,
                    action=util.as_url(post.keys.keys),
                    form_classes=".m-0",
                    submit_label="Delete key",
                    submit_classes="btn btn-sm btn-danger",
                    defaults={"fingerprint": key.fingerprint},
                    empty=True,
                )
            tbody.append(row.collect())

        page.div(".table-responsive.mb-5")[
            htm.table(".table.border.table-striped.table-hover.table-sm")[thead, tbody.collect()]
        ]
    else:
        page.p[htm.strong["You haven't added any personal OpenPGP keys yet."]]


def _ssh_keys(page: htm.Block, user_ssh_keys: list[sql.SSHKey]) -> None:
    page.h3["Your SSH keys"]
    if user_ssh_keys:
        grid = htm.Block(htm.div, classes=".d-grid.gap-4")
        for key in user_ssh_keys:
            card_block = htm.Block(htm.div, classes=f"#ssh-key-{key.fingerprint}.card.p-3.border")

            key_type = key.key.split()[0] if key.key else ""
            tbody = htm.tbody[
                htm.tr[
                    htm.th(".p-2.text-dark")["Fingerprint"],
                    htm.td(".text-break")[key.fingerprint],
                ],
                htm.tr[
                    htm.th(".p-2.text-dark")["Type"],
                    htm.td(".text-break")[key_type],
                ],
            ]
            card_block.table(".mb-0")[tbody]
            card_block.details(".mt-3.p-3.bg-light.rounded")[
                htm.summary(".fw-bold")["View whole key"],
                htm.pre(".mt-3")[key.key],
            ]

            form.render_block(
                card_block,
                model_cls=shared.keys.DeleteSSHKeyForm,
                action=util.as_url(post.keys.keys),
                form_classes=".mt-3",
                submit_label="Delete key",
                submit_classes="btn btn-danger",
                defaults={"fingerprint": key.fingerprint},
                empty=True,
            )
            grid.append(card_block.collect())

        page.div(".mb-5.p-4.bg-light.rounded")[grid.collect()]
    else:
        page.p[htm.strong["You haven't added any SSH keys yet."]]
