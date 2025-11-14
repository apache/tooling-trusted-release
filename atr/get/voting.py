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


import aiofiles.os
import htpy
import markupsafe

import atr.blueprints.get as get
import atr.construct as construct
import atr.db as db
import atr.db.interaction as interaction
import atr.form as form
import atr.get.compose as compose
import atr.get.keys as keys
import atr.htm as htm
import atr.models.sql as sql
import atr.post as post
import atr.shared as shared
import atr.template as template
import atr.util as util
import atr.web as web


@get.committer("/voting/<project_name>/<version_name>/<revision>")
async def selected_revision(
    session: web.Committer, project_name: str, version_name: str, revision: str
) -> web.WerkzeugResponse | str:
    await session.check_access(project_name)

    async with db.session() as data:
        match await interaction.release_ready_for_vote(
            session, project_name, version_name, revision, data, manual_vote=False
        ):
            case str() as error:
                return await session.redirect(
                    compose.selected,
                    error=error,
                    project_name=project_name,
                    version_name=version_name,
                    revision=revision,
                )
            case (release, committee):
                pass

        permitted_recipients = util.permitted_voting_recipients(session.uid, committee.name)

        min_hours = 72
        if release.release_policy and (release.release_policy.min_hours is not None):
            min_hours = release.release_policy.min_hours

        # TODO: Add the draft revision number or tag to the subject
        default_subject = f"[VOTE] Release {release.project.display_name} {release.version}"
        default_body = await construct.start_vote_default(project_name)

        keys_warning = await _check_keys_warning(committee)

        content = await _render_page(
            release=release,
            permitted_recipients=permitted_recipients,
            default_subject=default_subject,
            default_body=default_body,
            min_hours=min_hours,
            keys_warning=keys_warning,
        )

        return await template.blank(
            title=f"Start voting on {release.project.short_display_name} {release.version}", content=content
        )


async def _check_keys_warning(committee: sql.Committee) -> bool:
    if committee.is_podling:
        keys_file_path = util.get_downloads_dir() / "incubator" / committee.name / "KEYS"
    else:
        keys_file_path = util.get_downloads_dir() / committee.name / "KEYS"

    return not await aiofiles.os.path.isfile(keys_file_path)


async def _render_page(
    release,
    permitted_recipients: list[str],
    default_subject: str,
    default_body: str,
    min_hours: int,
    keys_warning: bool,
) -> htm.Element:
    page = htm.Block()

    back_link_url = util.as_url(
        compose.selected,
        project_name=release.project.name,
        version_name=release.version,
    )
    shared.distribution.html_nav(
        page,
        back_link_url,
        f"Compose {release.short_display_name}",
        "COMPOSE",
    )

    page.h1(".mb-4")[
        "Start voting on ",
        htm.strong[release.project.short_display_name],
        " ",
        htm.em[release.version],
    ]

    page.div(".px-3.py-4.mb-4.bg-light.border.rounded")[
        htm.p(".mb-0")[
            "Starting a vote for this draft release will cause an email to be sent to the appropriate mailing list, "
            "and advance the draft to the VOTE phase. Please note that this feature is currently in development."
        ]
    ]

    if keys_warning:
        keys_url = util.as_url(keys.keys) + f"#committee-{release.committee.name}"
        page.div(".p-3.mb-4.bg-warning-subtle.border.border-warning.rounded")[
            htm.strong["Warning: "],
            "The KEYS file is missing. Please autogenerate one on the ",
            htm.a(href=keys_url)["KEYS page"],
            ".",
        ]

    cancel_url = util.as_url(
        compose.selected,
        project_name=release.project.name,
        version_name=release.version,
    )

    custom_body_widget = _render_body_tabs(default_body)

    vote_form = form.render(
        model_cls=shared.voting.StartVotingForm,
        submit_label="Send vote email",
        cancel_url=cancel_url,
        defaults={
            "mailing_list": permitted_recipients,
            "vote_duration": min_hours,
            "subject": default_subject,
            "body": default_body,
        },
        custom={
            "body": custom_body_widget,
        },
    )
    page.append(vote_form)
    page.append(_render_javascript(release, min_hours))

    return page.collect()


def _render_body_tabs(default_body: str) -> htm.Element:
    """Render the tabbed interface for body editing and preview."""

    tabs_ul = htm.ul("#voteBodyTab.nav.nav-tabs", role="tablist")[
        htm.li(".nav-item", role="presentation")[
            htpy.button(
                "#edit-vote-body-tab.nav-link.active",
                data_bs_toggle="tab",
                data_bs_target="#edit-vote-body-pane",
                type="button",
                role="tab",
                aria_controls="edit-vote-body-pane",
                aria_selected="true",
            )["Edit"]
        ],
        htm.li(".nav-item", role="presentation")[
            htpy.button(
                "#text-preview-vote-body-tab.nav-link",
                data_bs_toggle="tab",
                data_bs_target="#text-preview-vote-body-pane",
                type="button",
                role="tab",
                aria_controls="text-preview-vote-body-pane",
                aria_selected="false",
            )["Text preview"]
        ],
    ]

    edit_pane = htm.div("#edit-vote-body-pane.tab-pane.fade.show.active", role="tabpanel")[
        htpy.textarea(
            "#body.form-control.font-monospace.mt-2",
            name="body",
            rows="12",
        )[default_body]
    ]

    preview_pane = htm.div("#text-preview-vote-body-pane.tab-pane.fade", role="tabpanel")[
        htm.pre(".mt-2.p-3.bg-light.border.rounded.font-monospace.overflow-auto")[
            htm.code("#vote-text-preview-content")["Loading preview..."]
        ]
    ]

    tab_content = htm.div("#voteBodyTabContent.tab-content")[edit_pane, preview_pane]

    return htm.div[tabs_ul, tab_content]


def _render_javascript(release, min_hours: int) -> htm.Element:
    """Render the JavaScript for email preview."""
    preview_url = util.as_url(
        post.preview.vote_preview, project_name=release.project.name, version_name=release.version
    )

    js_code = f"""
        document.addEventListener("DOMContentLoaded", () => {{
            let debounceTimeout;
            const debounceDelay = 500;

            const bodyTextarea = document.getElementById("body");
            const voteDurationInput = document.getElementById("vote_duration");
            const textPreviewContent = document.getElementById("vote-text-preview-content");
            const voteForm = document.querySelector("form.atr-canary");

            if (!bodyTextarea || !voteDurationInput || !textPreviewContent || !voteForm) {{
                console.error("Required elements for vote preview not found. Exiting.");
                return;
            }}

            const previewUrl = "{preview_url}";
            const csrfTokenInput = voteForm.querySelector('input[name="csrf_token"]');

            if (!previewUrl || !csrfTokenInput) {{
                console.error("Required data attributes or CSRF token not found for vote preview.");
                return;
            }}
            const csrfToken = csrfTokenInput.value;

            function fetchAndUpdateVotePreview() {{
                const bodyContent = bodyTextarea.value;
                const voteDuration = voteDurationInput.value || "{min_hours}";

                fetch(previewUrl, {{
                        method: "POST",
                        headers: {{
                            "Content-Type": "application/x-www-form-urlencoded",
                            "X-CSRFToken": csrfToken
                        }},
                        body: new URLSearchParams({{
                            "body": bodyContent,
                            "duration": voteDuration,
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
                debounceTimeout = setTimeout(fetchAndUpdateVotePreview, debounceDelay);
            }});

            voteDurationInput.addEventListener("input", () => {{
                clearTimeout(debounceTimeout);
                debounceTimeout = setTimeout(fetchAndUpdateVotePreview, debounceDelay);
            }});

            fetchAndUpdateVotePreview();
        }});
    """

    return htpy.script[markupsafe.Markup(js_code)]
