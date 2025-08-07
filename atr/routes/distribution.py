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
import datetime
import json

import aiohttp
import htpy
import pydantic
import quart

import atr.db as db
import atr.forms as forms
import atr.htm as htm
import atr.models.basic as basic
import atr.models.schema as schema
import atr.models.sql as sql
import atr.routes as routes
import atr.storage as storage
import atr.storage.outcome as outcome
import atr.template as template


class ArtifactHubAvailableVersion(schema.Lax):
    ts: int


class ArtifactHubResponse(schema.Lax):
    available_versions: list[ArtifactHubAvailableVersion] = pydantic.Field(default_factory=list)


class DockerResponse(schema.Lax):
    tag_last_pushed: str | None = None


class GitHubResponse(schema.Lax):
    published_at: str | None = None


class MavenDoc(schema.Lax):
    timestamp: int | None = None


class MavenResponse(schema.Lax):
    response: dict[str, list[MavenDoc]] = pydantic.Field(default_factory=dict)


class NpmResponse(schema.Lax):
    time: dict[str, str] = pydantic.Field(default_factory=dict)


class PyPIUrl(schema.Lax):
    upload_time_iso_8601: str | None = None


class PyPIResponse(schema.Lax):
    urls: list[PyPIUrl] = pydantic.Field(default_factory=list)


class DistributeForm(forms.Typed):
    platform = forms.select("Platform", choices=sql.DistributionPlatform)
    owner_namespace = forms.optional(
        "Owner or Namespace",
        placeholder="E.g. com.example or scope or library",
        description="Who owns or names the package (Maven groupId, npm @scope, "
        "Docker namespace, GitHub owner, ArtifactHub repo). Leave blank if not used.",
    )
    package = forms.string("Package", placeholder="E.g. artifactId or package-name")
    version = forms.string("Version", placeholder="E.g. 1.2.3, without a leading v")
    details = forms.checkbox("Include details", description="Include the details of the distribution in the response")
    submit = forms.submit("Record")

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


@dataclasses.dataclass
class FormProjectVersion:
    form: DistributeForm
    project: str
    version: str


# Lax to ignore csrf_token and submit
# WTForms types platform as Any, which is insufficient
# And this way we also get nice JSON from the Pydantic model dump
# Including all of the enum properties
class DistributeData(schema.Lax):
    platform: sql.DistributionPlatform
    owner_namespace: str | None = None
    package: str
    version: str
    details: bool

    @pydantic.field_validator("owner_namespace", mode="before")
    @classmethod
    def empty_to_none(cls, v):
        return None if v is None or (isinstance(v, str) and v.strip() == "") else v


@routes.committer("/distribution/record/<project>/<version>", methods=["GET"])
async def record(session: routes.CommitterSession, project: str, version: str) -> str:
    form = await DistributeForm.create_form(data={"package": project, "version": version})
    fpv = FormProjectVersion(form=form, project=project, version=version)
    return await _distribute_page(fpv)


@routes.committer("/distribution/record/<project>/<version>", methods=["POST"])
async def record_post(session: routes.CommitterSession, project: str, version: str) -> str:
    form = await DistributeForm.create_form(data=await quart.request.form)
    fpv = FormProjectVersion(form=form, project=project, version=version)
    if await form.validate():
        return await _distribute_post_validated(fpv)
    match len(form.errors):
        case 0:
            # Should not happen
            await quart.flash("Ambiguous submission errors", category="warning")
        case 1:
            await quart.flash("There was 1 submission error", category="error")
        case _ as n:
            await quart.flash(f"There were {n} submission errors", category="error")
    return await _distribute_page(fpv)


# This function is used in both GET and POST routes
async def _distribute_page(fpv: FormProjectVersion, *, extra_content: htpy.Element | None = None) -> str:
    # Validate the Release
    await _release_validated(fpv.project, fpv.version)

    # Render the explanation and form
    block = htm.Block()

    # Record a manual distribution
    block.h1["Record a manual distribution"]
    if extra_content:
        block.append(extra_content)
    block.p[
        "Record a manual distribution during the ",
        htpy.span(".atr-phase-three.atr-phase-label")["FINISH"],
        " phase using the form below.",
    ]
    block.append(forms.render_columns(fpv.form, action=quart.request.path, descriptions=True))

    # Render the page
    return await template.blank("Record a manual distribution", content=block.collect())


async def _distribute_post_api(
    api_url: str, platform: sql.DistributionPlatform, version: str
) -> outcome.Outcome[basic.JSON]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(api_url) as response:
                response.raise_for_status()
                response_json = await response.json()
        result = basic.as_json(response_json)
    except aiohttp.ClientError as e:
        return outcome.Error(e)
    match platform:
        case sql.DistributionPlatform.NPM | sql.DistributionPlatform.NPM_SCOPED:
            if version not in NpmResponse.model_validate(result).time:
                e = RuntimeError(f"Version '{version}' not found")
                return outcome.Error(e)
    return outcome.Result(result)


async def _distribute_post_validated(fpv: FormProjectVersion, /) -> str:
    dd = DistributeData.model_validate(fpv.form.data)
    release, committee = await _release_committee_validated(fpv.project, fpv.version)
    api_url = fpv.form.platform.data.value.template_url.format(
        owner_namespace=dd.owner_namespace,
        package=dd.package,
        version=dd.version,
    )
    api_oc = await _distribute_post_api(api_url, dd.platform, dd.version)

    block = htm.Block()

    # In case of error, show an alert
    def _alert(not_found: str, action: str) -> htpy.Element:
        div = htm.Block(htpy.div(".alert.alert-danger"))
        div.p[
            f"The {not_found} was not found in ",
            htpy.a(href=api_url)["the distribution platform API"],
            f". Please {action}.",
        ]
        return div.collect()

    # Distribution submitted
    block.h1["Distribution recorded"]
    match api_oc:
        case outcome.Result(result):
            block.p["The distribution was recorded successfully."]
        case outcome.Error():
            alert = _alert("package and version", "check the package name and version")
            return await _distribute_page(fpv, extra_content=alert)
        # We leak result, usefully, from this scope

    # This must come after the api_oc match, as it uses the result
    upload_date = _platform_upload_date(dd.platform, result, dd.version)
    if upload_date is None:
        # TODO: Add a link to an issue tracker
        alert = _alert("upload date", "report this bug to ASF Tooling")
        return await _distribute_page(fpv, extra_content=alert)

    async with storage.write_as_committee_member(committee_name=committee.name) as w:
        distribution = await w.distributions.add_distribution(
            release_name=release.name,
            platform=dd.platform,
            owner_namespace=dd.owner_namespace,
            package=dd.package,
            version=dd.version,
            staging=False,
            upload_date=upload_date,
            api_url=api_url,
        )

    ### Record
    block.h2["Record"]
    block.table(".table.table-striped.table-bordered")[
        htpy.tbody[
            _tr("Release name", distribution.release_name),
            _tr("Platform", distribution.platform.name),
            _tr("Owner or Namespace", distribution.owner_namespace or "-"),
            _tr("Package", distribution.package),
            _tr("Version", distribution.version),
            _tr("Staging", "No" if distribution.staging else "Yes"),
            _tr("Upload date", str(distribution.upload_date)),
            _tr("API URL", distribution.api_url),
        ]
    ]

    if dd.details:
        ## Details
        block.h2["Details"]

        ### Submitted values
        block.h3["Submitted values"]
        _distribute_post_table(block, dd)

        ### As JSON
        block.h3["As JSON"]
        block.pre(".mb-3")[dd.model_dump_json(indent=2)]

        ### API URL
        block.h3["API URL"]
        block.pre(".mb-3")[api_url]

        ### API response
        block.h3["API response"]
        block.details[
            htpy.summary["Show full API response"],
            htpy.pre(".atr-pre-wrap.mb-3")[json.dumps(result, indent=2)],
        ]

    return await template.blank("Distribution submitted", content=block.collect())


def _distribute_post_table(block: htm.Block, dd: DistributeData) -> None:
    tbody = htpy.tbody[
        _tr("Platform", dd.platform.name),
        _tr("Owner or Namespace", dd.owner_namespace or "-"),
        _tr("Package", dd.package),
        _tr("Version", dd.version),
    ]
    block.table(".table.table-striped.table-bordered")[tbody]


def _platform_upload_date(  # noqa: C901
    platform: sql.DistributionPlatform,
    data: basic.JSON,
    version: str,
) -> datetime.datetime | None:
    match platform:
        case sql.DistributionPlatform.ARTIFACTHUB:
            if not (versions := ArtifactHubResponse.model_validate(data).available_versions):
                return None
            return datetime.datetime.fromtimestamp(versions[0].ts, tz=datetime.UTC)
        case sql.DistributionPlatform.DOCKER:
            if not (pushed_at := DockerResponse.model_validate(data).tag_last_pushed):
                return None
            return datetime.datetime.fromisoformat(pushed_at.rstrip("Z"))
        case sql.DistributionPlatform.GITHUB:
            if not (published_at := GitHubResponse.model_validate(data).published_at):
                return None
            return datetime.datetime.fromisoformat(published_at.rstrip("Z"))
        case sql.DistributionPlatform.MAVEN:
            if not (docs := MavenResponse.model_validate(data).response.get("docs")):
                return None
            if not (timestamp := docs[0].timestamp):
                return None
            return datetime.datetime.fromtimestamp(timestamp / 1000, tz=datetime.UTC)
        case sql.DistributionPlatform.NPM | sql.DistributionPlatform.NPM_SCOPED:
            if not (times := NpmResponse.model_validate(data).time):
                return None
            # Versions can be in the form "1.2.3" or "v1.2.3", so we check for both
            if not (upload_time := times.get(version) or times.get(f"v{version}")):
                return None
            return datetime.datetime.fromisoformat(upload_time.rstrip("Z"))
        case sql.DistributionPlatform.PYPI:
            if not (urls := PyPIResponse.model_validate(data).urls):
                return None
            if not (upload_time := urls[0].upload_time_iso_8601):
                return None
            return datetime.datetime.fromisoformat(upload_time.rstrip("Z"))
    raise NotImplementedError(f"Platform {platform.name} is not yet supported")


async def _release_committee_validated(project: str, version: str) -> tuple[sql.Release, sql.Committee]:
    release = await _release_validated(project, version, committee=True)
    committee = release.committee
    if committee is None:
        raise RuntimeError(f"Release {project} {version} has no committee")
    return release, committee


async def _release_validated(project: str, version: str, committee: bool = False) -> sql.Release:
    async with db.session() as data:
        release = await data.release(
            project_name=project,
            version=version,
            _committee=committee,
        ).demand(RuntimeError(f"Release {project} {version} not found"))
        if release.phase != sql.ReleasePhase.RELEASE_PREVIEW:
            raise RuntimeError(f"Release {project} {version} is not a release preview")
        # if release.project.status != sql.ProjectStatus.ACTIVE:
        #     raise RuntimeError(f"Project {project} is not active")
    return release


def _tr(label: str, value: str) -> htpy.Element:
    return htpy.tr[htpy.th[label], htpy.td[value]]
