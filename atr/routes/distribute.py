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

from __future__ import annotations

import json
from typing import Final

import htpy
import quart

import atr.forms as forms
import atr.routes as routes
import atr.template as template

_PLATFORM_OPTIONS: Final[list[tuple[str, str]]] = [
    ("maven", "Maven Central"),
    ("pypi", "PyPI"),
    ("npm", "npm"),
    ("docker", "Docker"),
    ("artifacthub", "ArtifactHub (Helm)"),
    ("github", "GitHub"),
]


class DistributeForm(forms.Typed):
    platform = forms.select("Platform", choices=_PLATFORM_OPTIONS)
    owner_namespace = forms.string(
        "Owner or Namespace",
        optional=True,
        placeholder="E.g. com.example or @scope or library",
        description="Who owns or names the package (Maven groupId, npm @scope, "
        "Docker namespace, GitHub owner, ArtifactHub repo). Leave blank if not used.",
    )
    package = forms.string("Package", placeholder="E.g. artifactId or package-name")
    version = forms.string("Version", placeholder="E.g. 1.2.3 or v1.2.3")
    submit = forms.submit()


@routes.committer("/distribute/<project>/<version>", methods=["GET"])
async def distribute(session: routes.CommitterSession, project: str, version: str) -> str:
    return await _distribute_page(project=project, version=version)


@routes.committer("/distribute/<project>/<version>", methods=["POST"])
async def distribute_post(session: routes.CommitterSession, project: str, version: str) -> str:
    form = await DistributeForm.create_form()
    if await form.validate():
        return await _distribute_post_validated(form)
    # TODO: Show errors
    return await _distribute_page(project=project, version=version)


async def _distribute_page(*, project: str, version: str) -> str:
    form = await DistributeForm.create_form(data={"package": project, "version": version})
    form_content = forms.render_columns(form, action=quart.request.path, descriptions=True)
    introduction = htpy.p[
        """Record a manual distribution using the form below. Please note that
        this form is a work in progress and not fully functional."""
    ]
    content = _page("Distribute", introduction, form_content)
    return await template.blank("Distribute", content=content)


async def _distribute_post_validated(form: DistributeForm) -> str:
    data = {
        "platform": form.platform.data,
        "owner_namespace": form.owner_namespace.data,
        "package": form.package.data,
        "version": form.version.data,
    }
    table = _distribute_post_table(data)
    pre_json_results = htpy.pre[json.dumps(data, indent=2)]
    content = _page(
        "Submitted values",
        htpy.div[
            table,
            htpy.h2["As JSON"],
            pre_json_results,
        ],
    )
    return await template.blank("Distribution Submitted", content=content)


def _distribute_post_table(data: dict[str, str]) -> htpy.Element:
    def row(label: str, value: str) -> htpy.Element:
        return htpy.tr[htpy.th[label], htpy.td[value]]

    tbody = htpy.tbody[
        row("Platform", data["platform"]),
        row("Owner or Namespace", data["owner_namespace"] or "(blank)"),
        row("Package", data["package"]),
        row("Version", data["version"]),
    ]
    return htpy.table(".table.table-striped.table-bordered")[tbody]


def _page(title_str: str, *content: htpy.Element) -> htpy.Element:
    return htpy.div[htpy.h1[title_str], *content]
