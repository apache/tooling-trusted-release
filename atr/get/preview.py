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
import atr.get.finish as finish
import atr.htm as htm
import atr.models.sql as sql
import atr.shared as shared
import atr.template as template
import atr.util as util
import atr.web as web


@get.committer("/preview/view/<project_name>/<version_name>")
async def view(session: web.Committer, project_name: str, version_name: str) -> str:
    """View all the files in the rsync upload directory for a release."""
    await session.check_access(project_name)

    release = await session.release(project_name, version_name, phase=sql.ReleasePhase.RELEASE_PREVIEW)

    # Convert async generator to list
    # There must be a revision on a preview
    file_stats = [
        stat
        async for stat in util.content_list(
            util.get_unfinished_dir(), project_name, version_name, release.unwrap_revision_number
        )
    ]
    # Sort the files by FileStat.path
    file_stats.sort(key=lambda fs: fs.path)

    block = htm.Block()

    shared.distribution.html_nav(
        block,
        util.as_url(finish.selected, project_name=release.project.name, version_name=release.version),
        f"Finish {release.short_display_name}",
        "FINISH",
    )

    block.h1[
        "Files in ",
        htm.strong[release.project.short_display_name],
        " ",
        htm.em[release.version],
    ]

    block.div(".card.mb-4")[
        htm.div(".card-header.d-flex.justify-content-between.align-items-center")[
            htm.h3(".mb-0")["Release information"]
        ],
        htm.div(".card-body")[
            htm.div(".row")[
                htm.div(".col-md-6")[
                    htm.p[htm.strong["Project:"], " ", release.project.display_name],
                    htm.p[htm.strong["Label:"], " ", release.name],
                ],
                htm.div(".col-md-6")[
                    htm.p[htm.strong["Created:"], " ", release.created.strftime("%Y-%m-%d %H:%M:%S")],
                ],
            ]
        ],
    ]

    files_card = htm.Block(htm.div, classes=".card.mb-4")
    files_card.div(".card-header.d-flex.justify-content-between.align-items-center")[htm.h3(".mb-0")["Files"]]

    if file_stats:
        tbody = htm.Block(htm.tbody)
        for stat in file_stats:
            if stat.is_file:
                file_url = util.as_url(
                    view_path,
                    project_name=release.project.name,
                    version_name=release.version,
                    file_path=stat.path,
                )
                file_link = htm.a(href=file_url)[stat.path]
            else:
                file_link = htm.strong[stat.path + "/"]

            tbody.tr[
                htm.td[util.format_permissions(stat.permissions)],
                htm.td[file_link],
                htm.td[util.format_file_size(stat.size) if stat.is_file else "-"],
                htm.td[util.format_datetime(stat.modified)],
            ]

        files_card.div(".card-body")[
            htm.div(".table-responsive")[
                htm.table(".table.table-striped.table-hover")[
                    htm.thead[
                        htm.tr[
                            htm.th["Permissions"],
                            htm.th["File path"],
                            htm.th["Size"],
                            htm.th["Modified"],
                        ]
                    ],
                    tbody.collect(),
                ]
            ]
        ]
    else:
        files_card.div(".card-body")[htm.div(".alert.alert-info")["This release preview does not have any files."]]

    block.append(files_card.collect())

    return await template.blank(
        f"Files in {release.short_display_name}",
        content=block.collect(),
    )


@get.committer("/preview/view/<project_name>/<version_name>/<path:file_path>")
async def view_path(session: web.Committer, project_name: str, version_name: str, file_path: str) -> str:
    """View the content of a specific file in the release preview."""
    await session.check_access(project_name)

    release = await session.release(project_name, version_name, phase=sql.ReleasePhase.RELEASE_PREVIEW)
    _max_view_size = 1 * 1024 * 1024
    full_path = util.release_directory(release) / file_path
    content_listing = await util.archive_listing(full_path)
    content, is_text, is_truncated, error_message = await util.read_file_for_viewer(full_path, _max_view_size)

    block = htm.Block()

    back_url = util.as_url(
        view,
        project_name=release.project.name,
        version_name=release.version,
    )
    block.a(href=back_url, class_="atr-back-link")["← Back to preview"]

    block.div(".p-3.mt-4.mb-4.bg-light.border.rounded")[
        htm.h2(".mt-0")[f"Viewing file: {file_path}"],
        htm.p(".mb-0")[htm.strong["Release:"], " ", release.name],
    ]

    if content_listing:
        items = [htm.li(".list-group-item.py-1.px-3.small")[item] for item in content_listing]
        block.div(".card.mb-3")[
            htm.div(".card-header")[htm.h3(".mb-0")[f"Archive contents ({len(content_listing)})"]],
            htm.div(".card-body.p-0")[htm.ul(".list-group.list-group-flush")[*items]],
        ]

    if error_message:
        block.div(".alert.alert-danger")[error_message]
    elif content is not None:
        if content_listing:
            details_block = htm.Block(htm.details, classes=".mb-3")
            details_block.summary(".mb-2")["View raw file content"]
            _render_file_content(details_block, content, is_text, is_truncated, _max_view_size)
            block.append(details_block.collect())
        else:
            _render_file_content(block, content, is_text, is_truncated, _max_view_size)
    else:
        block.div(".alert.alert-secondary")["No content available for this file."]

    return await template.blank(
        f"View {release.project.short_display_name}/{release.version}/{file_path}",
        content=block.collect(),
    )


def _render_file_content(block: htm.Block, content: str, is_text: bool, is_truncated: bool, max_view_size: int) -> None:
    card = htm.Block(htm.div, classes=".card.mb-4")
    card.div(".card-header")[htm.h3(".mb-0")["File content" + (" (Hexdump)" if not is_text else "")]]

    if is_text:
        card.div(".card-body.p-0")[htm.pre(".bg-light.p-4.rounded-bottom.mb-0.text-break")[content]]
    else:
        card.div(".card-body.p-0")[htm.pre(".bg-light.p-4.rounded-bottom.mb-0.text-break")[htm.code[content]]]

    if is_truncated:
        card.div(".card-footer.text-muted.small")[
            f"Note: File content truncated to the first {util.format_file_size(max_view_size)}."
        ]

    block.append(card.collect())
