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


import htpy
import markupsafe

# TODO: Improve upon the routes_release pattern
import atr.blueprints.get as get
import atr.config as config
import atr.construct as construct
import atr.form as form
import atr.htm as htm
import atr.models.sql as sql
import atr.post as post
import atr.shared as shared
import atr.shared.distribution as distribution
import atr.template as template
import atr.util as util
import atr.web as web


@get.committer("/announce/<project_name>/<version_name>")
async def selected(session: web.Committer, project_name: str, version_name: str) -> str | web.WerkzeugResponse:
    """Allow the user to announce a release preview."""
    await session.check_access(project_name)

    release = await session.release(
        project_name, version_name, with_committee=True, phase=sql.ReleasePhase.RELEASE_PREVIEW
    )

    # Variables used in defaults for subject and body
    project_display_name = release.project.display_name or release.project.name

    # The subject cannot be changed by the user
    default_subject = f"[ANNOUNCE] {project_display_name} {version_name} released"
    # The body can be changed, either from VoteTemplate or from the form
    default_body = await construct.announce_release_default(project_name)

    # The download path suffix can be changed
    # The defaults depend on whether the project is top level or not
    if (committee := release.project.committee) is None:
        raise ValueError("Release has no committee")
    top_level_project = release.project.name == util.unwrap(committee.name)
    # These defaults are as per #136, but we allow the user to change the result
    default_download_path_suffix = "/" if top_level_project else f"/{release.project.name}-{release.version}/"

    # This must NOT end with a "/"
    description_download_prefix = f"https://{config.get().APP_HOST}/downloads"
    if committee.is_podling:
        description_download_prefix += "/incubator"
    description_download_prefix += f"/{committee.name}"

    permitted_recipients = util.permitted_announce_recipients(session.uid)
    mailing_list_choices = sorted([(recipient, recipient) for recipient in permitted_recipients])

    content = await _render_page(
        release=release,
        mailing_list_choices=mailing_list_choices,
        default_subject=default_subject,
        default_body=default_body,
        default_download_path_suffix=default_download_path_suffix,
        download_path_description=f"The URL will be {description_download_prefix} plus this suffix",
    )

    return await template.blank(
        title=f"Announce and distribute {release.project.display_name} {release.version}",
        description=f"Announce and distribute {release.project.display_name} {release.version} as a release.",
        content=content,
    )


async def _render_page(
    release: sql.Release,
    mailing_list_choices: list[tuple[str, str]],
    default_subject: str,
    default_body: str,
    default_download_path_suffix: str,
    download_path_description: str,
) -> htm.Element:
    """Render the announce page."""
    page = htm.Block()

    page_styles = """
        .page-preview-meta-item::after {
            content: "•";
            margin-left: 1rem;
            color: #ccc;
        }
        .page-preview-meta-item:last-child::after {
            content: none;
        }
    """
    page.style[markupsafe.Markup(page_styles)]

    distribution.html_nav_phase(page, release.project.name, release.version, staging=False)

    page.h1[
        "Announce ",
        htm.strong[release.project.short_display_name],
        " ",
        htm.em[release.version],
    ]
    page.append(_render_release_card(release))
    page.h2["Announce this release"]
    page.p[f"This form will send an announcement to the ASF {util.USER_TESTS_ADDRESS} mailing list."]

    # Custom widget for body tabs and mailing list with warning
    custom_body_widget = _render_body_tabs(default_body)
    custom_mailing_list_widget = _render_mailing_list_with_warning(mailing_list_choices, util.USER_TESTS_ADDRESS)

    # Custom widget for download_path_suffix with custom documentation
    download_path_widget = _render_download_path_field(default_download_path_suffix, download_path_description)

    defaults_dict = {
        "revision_number": release.unwrap_revision_number,
        "subject": default_subject,
        "body": default_body,
    }

    form.render_block(
        page,
        model_cls=shared.announce.AnnounceForm,
        action=util.as_url(post.announce.selected, project_name=release.project.name, version_name=release.version),
        submit_label="Send announcement email",
        defaults=defaults_dict,
        custom={
            "body": custom_body_widget,
            "mailing_list": custom_mailing_list_widget,
            "download_path_suffix": download_path_widget,
        },
        form_classes=".atr-canary.py-4.px-5.mb-4.border.rounded",
        border=True,
        wider_widgets=True,
    )

    page.append(_render_javascript(release, download_path_description))
    return page.collect()


def _render_release_card(release: sql.Release) -> htm.Element:
    """Render the release information card."""
    card = htm.div(f"#{release.name}.card.mb-4.shadow-sm")[
        htm.div(".card-header.bg-light")[htm.h3(".card-title.mb-0")["About this release preview"]],
        htm.div(".card-body")[
            htm.div(".d-flex.flex-wrap.gap-3.pb-1.text-secondary.fs-6")[
                htm.span(".page-preview-meta-item")[f"Revision: {release.latest_revision_number}"],
                htm.span(".page-preview-meta-item")[f"Created: {release.created.strftime('%Y-%m-%d %H:%M:%S UTC')}"],
            ],
        ],
    ]
    return card


def _render_body_tabs(default_body: str) -> htm.Element:
    """Render the tabbed interface for body editing and preview."""

    tabs_ul = htm.ul("#announceBodyTab.nav.nav-tabs", role="tablist")[
        htm.li(".nav-item", role="presentation")[
            htpy.button(
                "#edit-announce-body-tab.nav-link.active",
                data_bs_toggle="tab",
                data_bs_target="#edit-announce-body-pane",
                type="button",
                role="tab",
                aria_controls="edit-announce-body-pane",
                aria_selected="true",
            )["Edit"]
        ],
        htm.li(".nav-item", role="presentation")[
            htpy.button(
                "#text-preview-announce-body-tab.nav-link",
                data_bs_toggle="tab",
                data_bs_target="#text-preview-announce-body-pane",
                type="button",
                role="tab",
                aria_controls="text-preview-announce-body-pane",
                aria_selected="false",
            )["Text preview"]
        ],
    ]

    edit_pane = htm.div("#edit-announce-body-pane.tab-pane.fade.show.active", role="tabpanel")[
        htpy.textarea(
            "#body.form-control.font-monospace.mt-2",
            name="body",
            rows="12",
        )[default_body]
    ]

    preview_pane = htm.div("#text-preview-announce-body-pane.tab-pane.fade", role="tabpanel")[
        htm.pre(".mt-2.p-3.bg-light.border.rounded.font-monospace.overflow-auto")[
            htm.code("#announce-text-preview-content")["Loading preview..."]
        ]
    ]

    tab_content = htm.div("#announceBodyTabContent.tab-content")[edit_pane, preview_pane]

    return htm.div[tabs_ul, tab_content]


def _render_mailing_list_with_warning(choices: list[tuple[str, str]], default_value: str) -> htm.Element:
    """Render the mailing list radio buttons with a warning card."""
    container = htm.Block(htm.div)

    # Radio buttons
    radio_container = htm.div(".d-flex.flex-wrap.gap-2.mb-3")
    radio_buttons = []
    for value, label in choices:
        radio_id = f"mailing_list_{value}"
        radio_attrs = {
            "type": "radio",
            "name": "mailing_list",
            "value": value,
        }
        if value == default_value:
            radio_attrs["checked"] = ""

        radio_buttons.append(
            htm.div(".form-check")[
                htpy.input(f"#{radio_id}.form-check-input", **radio_attrs),
                htpy.label(".form-check-label", for_=radio_id)[label],
            ]
        )
    container.append(radio_container[radio_buttons])

    # Warning card
    warning_card = htm.div(".card.bg-warning-subtle.mb-3")[
        htm.span(".card-body.p-3")[
            htpy.i(".bi.bi-exclamation-triangle.me-1"),
            htm.strong["TODO: "],
            "The limited options above are provided for testing purposes. In the finished version of ATR, "
            "you will be able to send to your own specified mailing lists.",
        ]
    ]
    container.append(warning_card)

    return container.collect()


def _render_download_path_field(default_value: str, description: str) -> htm.Element:
    """Render the download path suffix field with custom help text."""
    return htm.div[
        htpy.input(
            "#download_path_suffix.form-control",
            type="text",
            name="download_path_suffix",
            value=default_value,
        ),
        htm.div(".form-text.text-muted.mt-2")[description],
    ]


def _render_javascript(release: sql.Release, download_path_description: str) -> htm.Element:
    """Render the JavaScript for email preview and path validation."""
    preview_url = util.as_url(
        post.preview.announce_preview, project_name=release.project.name, version_name=release.version
    )
    base_text = (
        download_path_description.split(" plus this suffix")[0]
        if " plus this suffix" in download_path_description
        else download_path_description
    )

    js_code = f"""
        document.addEventListener("DOMContentLoaded", () => {{
            let debounceTimeout;
            const debounceDelay = 500;

            const bodyTextarea = document.getElementById("body");
            const textPreviewContent = document.getElementById("announce-text-preview-content");
            const announceForm = document.querySelector("form.atr-canary");

            if (!bodyTextarea || !textPreviewContent || !announceForm) {{
                console.error("Required elements for announce preview not found. Exiting.");
                return;
            }}

            const previewUrl = "{preview_url}";
            const csrfTokenInput = announceForm.querySelector('input[name="csrf_token"]');

            if (!previewUrl || !csrfTokenInput) {{
                console.error("Required data attributes or CSRF token not found for announce preview.");
                return;
            }}
            const csrfToken = csrfTokenInput.value;

            function fetchAndUpdateAnnouncePreview() {{
                const bodyContent = bodyTextarea.value;

                fetch(previewUrl, {{
                        method: "POST",
                        headers: {{
                            "Content-Type": "application/x-www-form-urlencoded",
                            "X-CSRFToken": csrfToken
                        }},
                        body: new URLSearchParams({{
                            "body": bodyContent,
                            "csrf_token": csrfToken
                        }})
                    }})
                    .then(response => {{
                        if (!response.ok) {{
                            return response.text().then(text => {{
                                throw new Error(`HTTP error ${{response.status}}: ${{text}}`)
                            }});
                        }}
                        return response.text();
                    }})
                    .then(previewText => {{
                        textPreviewContent.textContent = previewText;
                    }})
                    .catch(error => {{
                        console.error("Error fetching email preview:", error);
                        textPreviewContent.textContent = `Error loading preview:\\n${{error.message}}`;
                    }});
            }}

            bodyTextarea.addEventListener("input", () => {{
                clearTimeout(debounceTimeout);
                debounceTimeout = setTimeout(fetchAndUpdateAnnouncePreview, debounceDelay);
            }});

            fetchAndUpdateAnnouncePreview();

            const pathInput = document.getElementById("download_path_suffix");
            const pathHelpText = pathInput ? pathInput.parentElement.querySelector(".form-text") : null;

            if (pathInput && pathHelpText) {{
                const baseText = "{base_text}";
                let pathDebounce;

                function updatePathHelpText() {{
                    let suffix = pathInput.value;
                    if (suffix.includes("..") || suffix.includes("//")) {{
                        pathHelpText.textContent = "Download path suffix must not contain .. or //";
                        return;
                    }}
                    if (suffix.startsWith("./")) {{
                        suffix = suffix.substring(1);
                    }} else if (suffix === ".") {{
                        suffix = "/";
                    }}
                    if (!suffix.startsWith("/")) {{
                        suffix = "/" + suffix;
                    }}
                    if (!suffix.endsWith("/")) {{
                        suffix = suffix + "/";
                    }}
                    if (suffix.includes("/.")) {{
                        pathHelpText.textContent = "Download path suffix must not contain /.";
                        return;
                    }}
                    pathHelpText.textContent = baseText + suffix;
                }}

                pathInput.addEventListener("input", () => {{
                    clearTimeout(pathDebounce);
                    pathDebounce = setTimeout(updatePathHelpText, 10);
                }});
                updatePathHelpText();
            }}
        }});
    """

    return htpy.script[markupsafe.Markup(js_code)]
