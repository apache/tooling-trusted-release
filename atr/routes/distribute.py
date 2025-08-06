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

import dataclasses
import enum
import json

import htpy
import quart

import atr.db as db
import atr.forms as forms
import atr.models.sql as sql
import atr.routes as routes
import atr.template as template


@dataclasses.dataclass(frozen=True)
class PlatformValue:
    name: str
    template_url: str
    requires_owner_namespace: bool = False
    default_owner_namespace: str | None = None


class Platform(enum.Enum):
    MAVEN = PlatformValue(
        name="Maven Central",
        template_url="https://search.maven.org/solrsearch/select?q=g:{owner_namespace}+AND+a:{package}+AND+v:{version}&core=gav&rows=20&wt=json",
        requires_owner_namespace=True,
    )
    PYPI = PlatformValue(
        name="PyPI",
        template_url="https://pypi.org/pypi/{package}/{version}/json",
    )
    NPM_SCOPED = PlatformValue(
        name="npm (scoped)",
        template_url="https://registry.npmjs.org/@{owner_namespace}/{package}/{version}",
        requires_owner_namespace=True,
    )
    NPM = PlatformValue(
        name="npm",
        template_url="https://registry.npmjs.org/{package}/{version}",
    )
    DOCKER = PlatformValue(
        name="Docker",
        template_url="https://hub.docker.com/v2/namespaces/{owner_namespace}/repositories/{package}/tags/{version}",
        default_owner_namespace="library",
    )
    ARTIFACTHUB = PlatformValue(
        name="ArtifactHub (Helm)",
        template_url="https://artifacthub.io/api/v1/packages/helm/{owner_namespace}/{package}/{version}",
        requires_owner_namespace=True,
    )
    GITHUB = PlatformValue(
        name="GitHub",
        template_url="https://api.github.com/repos/{owner_namespace}/{package}/releases/tags/v{version}",
        requires_owner_namespace=True,
    )


class DistributeForm(forms.Typed):
    platform = forms.select("Platform", choices=Platform)
    owner_namespace = forms.string(
        "Owner or Namespace",
        optional=True,
        placeholder="E.g. com.example or @scope or library",
        description="Who owns or names the package (Maven groupId, npm @scope, "
        "Docker namespace, GitHub owner, ArtifactHub repo). Leave blank if not used.",
    )
    package = forms.string("Package", placeholder="E.g. artifactId or package-name")
    version = forms.string("Version", placeholder="E.g. 1.2.3, without a leading v")
    submit = forms.submit()

    async def validate(self, extra_validators: dict | None = None) -> bool:
        if not await super().validate(extra_validators):
            return False
        if not self.platform.data:
            return False
        default_owner_namespace = self.platform.data.value.default_owner_namespace
        requires_owner_namespace = self.platform.data.value.requires_owner_namespace
        owner_namespace = self.owner_namespace.data
        # TODO: We should disable the owner_namespace field if it's not required
        # But that would be a lot of complexity
        # And this validation, which we need to keep, is complex enough
        if default_owner_namespace and (not owner_namespace):
            self.owner_namespace.data = default_owner_namespace
        if requires_owner_namespace and (not owner_namespace):
            msg = f'Platform "{self.platform.data.name}" requires an owner or namespace.'
            return forms.error(self.owner_namespace, msg)
        if (not requires_owner_namespace) and (not default_owner_namespace) and owner_namespace:
            msg = f'Platform "{self.platform.data.name}" does not require an owner or namespace.'
            return forms.error(self.owner_namespace, msg)
        return True


@routes.committer("/distribute/<project>/<version>", methods=["GET"])
async def distribute(session: routes.CommitterSession, project: str, version: str) -> str:
    form = await DistributeForm.create_form(data={"package": project, "version": version})
    return await _distribute_page(project=project, version=version, form=form)


@routes.committer("/distribute/<project>/<version>", methods=["POST"])
async def distribute_post(session: routes.CommitterSession, project: str, version: str) -> str:
    form = await DistributeForm.create_form(data=await quart.request.form)
    if await form.validate():
        return await _distribute_post_validated(form)
    match len(form.errors):
        case 0:
            # Should not happen
            await quart.flash("Ambiguous submission errors", category="warning")
        case 1:
            await quart.flash("There was 1 submission error", category="error")
        case _ as n:
            await quart.flash(f"There were {n} submission errors", category="error")
    return await _distribute_page(project=project, version=version, form=form)


async def _distribute_page(*, project: str, version: str, form: DistributeForm) -> str:
    # Used in the GET and POST routes
    async with db.session() as data:
        release = await data.release(project_name=project, version=version).demand(
            RuntimeError(f"Release {project} {version} not found")
        )
        if release.phase != sql.ReleasePhase.RELEASE_PREVIEW:
            raise RuntimeError(f"Release {project} {version} is not a release preview")
        # if release.project.status != sql.ProjectStatus.ACTIVE:
        #     raise RuntimeError(f"Project {project} is not active")
    form_content = forms.render_columns(form, action=quart.request.path, descriptions=True)
    introduction = [
        htpy.p[
            "Record a manual distribution during the ",
            htpy.span(".atr-phase-three.atr-phase-label")["FINISH"],
            " phase using the form below.",
        ],
        htpy.p["Please note that this form is a work in progress and not fully functional."],
    ]
    content = _page("Record a manual distribution", *introduction, form_content)
    return await template.blank("Distribute", content=content)


async def _distribute_post_validated(form: DistributeForm) -> str:
    data = {
        "platform": form.platform.data,
        "owner_namespace": form.owner_namespace.data,
        "package": form.package.data,
        "version": form.version.data,
    }
    table = _distribute_post_table(data)
    pre_json_results = htpy.pre[
        json.dumps({k: str(v.name if isinstance(v, enum.Enum) else v) for k, v in data.items()}, indent=2)
    ]
    content = _page(
        "Submitted values",
        htpy.div[
            table,
            htpy.h2["As JSON"],
            pre_json_results,
        ],
        htpy.pre[
            form.platform.data.value.template_url.format(
                owner_namespace=data["owner_namespace"],
                package=data["package"],
                version=data["version"],
            ),
        ],
    )
    return await template.blank("Distribution Submitted", content=content)


def _distribute_post_table(data: dict[str, str | Platform]) -> htpy.Element:
    def row(label: str, value: str | Platform) -> htpy.Element:
        if isinstance(value, Platform):
            return htpy.tr[htpy.th[label], htpy.td[value.name]]
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
