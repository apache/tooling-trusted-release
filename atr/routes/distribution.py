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
from typing import TYPE_CHECKING, Literal

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
import atr.routes.compose as compose
import atr.routes.finish as finish
import atr.storage as storage
import atr.storage.outcome as outcome
import atr.template as template
import atr.util as util

if TYPE_CHECKING:
    import werkzeug.wrappers.response as response

type Phase = Literal["COMPOSE", "VOTE", "FINISH"]


class ArtifactHubAvailableVersion(schema.Lax):
    ts: int


class ArtifactHubLink(schema.Lax):
    url: str | None = None
    name: str | None = None


class ArtifactHubRepository(schema.Lax):
    name: str | None = None


class ArtifactHubResponse(schema.Lax):
    available_versions: list[ArtifactHubAvailableVersion] = pydantic.Field(default_factory=list)
    home_url: str | None = None
    links: list[ArtifactHubLink] = pydantic.Field(default_factory=list)
    name: str | None = None
    version: str | None = None
    repository: ArtifactHubRepository | None = None


class DockerResponse(schema.Lax):
    tag_last_pushed: str | None = None


class GitHubResponse(schema.Lax):
    published_at: str | None = None
    html_url: str | None = None


class MavenDoc(schema.Lax):
    timestamp: int | None = None


class MavenResponseBody(schema.Lax):
    start: int | None = None
    docs: list[MavenDoc] = pydantic.Field(default_factory=list)


class MavenResponse(schema.Lax):
    response: MavenResponseBody = pydantic.Field(default_factory=MavenResponseBody)


class NpmResponse(schema.Lax):
    name: str | None = None
    time: dict[str, str] = pydantic.Field(default_factory=dict)
    homepage: str | None = None


class PyPIUrl(schema.Lax):
    upload_time_iso_8601: str | None = None
    url: str | None = None


class PyPIInfo(schema.Lax):
    release_url: str | None = None
    project_url: str | None = None


class PyPIResponse(schema.Lax):
    urls: list[PyPIUrl] = pydantic.Field(default_factory=list)
    info: PyPIInfo = pydantic.Field(default_factory=PyPIInfo)


class DeleteForm(forms.Typed):
    release_name = forms.hidden()
    platform = forms.hidden()
    owner_namespace = forms.hidden()
    package = forms.hidden()
    version = forms.hidden()
    submit = forms.submit("Delete")


class DeleteData(schema.Lax):
    release_name: str
    platform: sql.DistributionPlatform
    owner_namespace: str
    package: str
    version: str

    @pydantic.field_validator("platform", mode="before")
    @classmethod
    def coerce_platform(cls, v: object) -> object:
        if isinstance(v, str):
            return sql.DistributionPlatform[v]
        return v


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
    submit = forms.submit("Record distribution")

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


@routes.committer("/distribution/delete/<project>/<version>", methods=["POST"])
async def delete(session: routes.CommitterSession, project: str, version: str) -> response.Response:
    form = await DeleteForm.create_form(data=await quart.request.form)
    dd = DeleteData.model_validate(form.data)

    # Validate the submitted data, and obtain the committee for its name
    async with db.session() as data:
        release = await data.release(name=dd.release_name).demand(RuntimeError(f"Release {dd.release_name} not found"))
    committee = release.committee
    if committee is None:
        raise RuntimeError(f"Release {dd.release_name} has no committee")

    # Delete the distribution
    async with storage.write_as_committee_member(committee_name=committee.name) as wacm:
        await wacm.distributions.delete_distribution(
            release_name=dd.release_name,
            platform=dd.platform,
            owner_namespace=dd.owner_namespace,
            package=dd.package,
            version=dd.version,
        )
    return await session.redirect(
        list_get,
        project=project,
        version=version,
        success="Distribution deleted",
    )


@routes.committer("/distributions/list/<project>/<version>", methods=["GET"])
async def list_get(session: routes.CommitterSession, project: str, version: str) -> str:
    async with db.session() as data:
        distributions = await data.distribution(
            release_name=sql.release_name(project, version),
        ).all()

    block = htm.Block()

    release = await _release_validated(project, version, staging=None)
    staging = release.phase == sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
    _html_nav_phase(block, project, version, staging)

    record_a_distribution = htpy.a(
        ".btn.btn-primary",
        href=util.as_url(
            stage if staging else record,
            project=project,
            version=version,
        ),
    )["Record a distribution"]

    # Distribution list for project-version
    block.h1["Distribution list for ", htpy.em[f"{project}-{version}"]]
    if not distributions:
        block.p["No distributions found."]
        block.p[record_a_distribution]
        return await template.blank(
            "Distribution list",
            content=block.collect(),
        )
    block.p["Here are all of the distributions recorded for this release."]
    block.p[record_a_distribution]
    # Table of contents
    ul_toc = htm.Block(htpy.ul)
    for distribution in distributions:
        a = htpy.a(href=f"#distribution-{distribution.identifier}")[distribution.title]
        ul_toc.li[a]
    block.append(ul_toc)

    ## Distributions
    block.h2["Distributions"]
    for distribution in distributions:
        delete_form = await DeleteForm.create_form(
            data={
                "release_name": distribution.release_name,
                "platform": distribution.platform.name,
                "owner_namespace": distribution.owner_namespace,
                "package": distribution.package,
                "version": distribution.version,
            }
        )

        ### Platform package version
        block.h3(
            # Cannot use "#id" here, because the ID contains "."
            # If an ID contains ".", htpy parses that as a class
            id=f"distribution-{distribution.identifier}"
        )[distribution.title]
        tbody = htpy.tbody[
            _html_tr("Release name", distribution.release_name),
            _html_tr("Platform", distribution.platform.value.name),
            _html_tr("Owner or Namespace", distribution.owner_namespace or "-"),
            _html_tr("Package", distribution.package),
            _html_tr("Version", distribution.version),
            _html_tr("Staging", "Yes" if distribution.staging else "No"),
            _html_tr("Upload date", str(distribution.upload_date)),
            _html_tr_a("API URL", distribution.api_url),
            _html_tr_a("Web URL", distribution.web_url),
        ]
        block.table(".table.table-striped.table-bordered")[tbody]
        form_action = util.as_url(delete, project=project, version=version)
        delete_form_element = forms.render_simple(
            delete_form,
            action=form_action,
            submit_classes="btn-danger",
        )
        block.append(htpy.div(".mb-3")[delete_form_element])

    title = f"Distribution list for {project} {version}"
    return await template.blank(title, content=block.collect())


@routes.committer("/distribution/record/<project>/<version>", methods=["GET"])
async def record(session: routes.CommitterSession, project: str, version: str) -> str:
    form = await DistributeForm.create_form(data={"package": project, "version": version})
    fpv = FormProjectVersion(form=form, project=project, version=version)
    return await _record_form_page(fpv)


@routes.committer("/distribution/record/<project>/<version>", methods=["POST"])
async def record_post(session: routes.CommitterSession, project: str, version: str) -> str:
    form = await DistributeForm.create_form(data=await quart.request.form)
    fpv = FormProjectVersion(form=form, project=project, version=version)
    if await form.validate():
        return await _record_form_process_page(fpv)
    match len(form.errors):
        case 0:
            # Should not happen
            await quart.flash("Ambiguous submission errors", category="warning")
        case 1:
            await quart.flash("There was 1 submission error", category="error")
        case _ as n:
            await quart.flash(f"There were {n} submission errors", category="error")
    return await _record_form_page(fpv)


@routes.committer("/distribution/stage/<project>/<version>", methods=["GET"])
async def stage(session: routes.CommitterSession, project: str, version: str) -> str:
    form = await DistributeForm.create_form(data={"package": project, "version": version})
    fpv = FormProjectVersion(form=form, project=project, version=version)
    return await _record_form_page(fpv, staging=True)


@routes.committer("/distribution/stage/<project>/<version>", methods=["POST"])
async def stage_post(session: routes.CommitterSession, project: str, version: str) -> str:
    form = await DistributeForm.create_form(data=await quart.request.form)
    fpv = FormProjectVersion(form=form, project=project, version=version)
    if await form.validate():
        return await _record_form_process_page(fpv, staging=True)
    match len(form.errors):
        case 0:
            await quart.flash("Ambiguous submission errors", category="warning")
        case 1:
            await quart.flash("There was 1 submission error", category="error")
        case _ as n:
            await quart.flash(f"There were {n} submission errors", category="error")
    return await _record_form_page(fpv, staging=True)


def _distribution_upload_date(  # noqa: C901
    platform: sql.DistributionPlatform,
    data: basic.JSON,
    version: str,
) -> datetime.datetime | None:
    match platform:
        case sql.DistributionPlatform.ARTIFACT_HUB:
            if not (versions := ArtifactHubResponse.model_validate(data).available_versions):
                return None
            return datetime.datetime.fromtimestamp(versions[0].ts, tz=datetime.UTC)
        case sql.DistributionPlatform.DOCKER_HUB:
            if not (pushed_at := DockerResponse.model_validate(data).tag_last_pushed):
                return None
            return datetime.datetime.fromisoformat(pushed_at.rstrip("Z"))
        case sql.DistributionPlatform.GITHUB:
            if not (published_at := GitHubResponse.model_validate(data).published_at):
                return None
            return datetime.datetime.fromisoformat(published_at.rstrip("Z"))
        case sql.DistributionPlatform.MAVEN:
            m = MavenResponse.model_validate(data)
            docs = m.response.docs
            if not docs:
                return None
            timestamp = docs[0].timestamp
            if not timestamp:
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


def _distribution_web_url(  # noqa: C901
    platform: sql.DistributionPlatform,
    data: basic.JSON,
    version: str,
) -> str | None:
    match platform:
        case sql.DistributionPlatform.ARTIFACT_HUB:
            ah = ArtifactHubResponse.model_validate(data)
            repo_name = ah.repository.name if ah.repository else None
            pkg_name = ah.name
            ver = ah.version
            if repo_name and pkg_name:
                if ver:
                    return f"https://artifacthub.io/packages/helm/{repo_name}/{pkg_name}/{ver}"
                return f"https://artifacthub.io/packages/helm/{repo_name}/{pkg_name}/{version}"
            if ah.home_url:
                return ah.home_url
            for link in ah.links:
                if link.url:
                    return link.url
            return None
        case sql.DistributionPlatform.DOCKER_HUB:
            # The best we can do on Docker Hub is:
            # f"https://hub.docker.com/_/{package}"
            return None
        case sql.DistributionPlatform.GITHUB:
            gh = GitHubResponse.model_validate(data)
            return gh.html_url
        case sql.DistributionPlatform.MAVEN:
            return None
        case sql.DistributionPlatform.NPM:
            nr = NpmResponse.model_validate(data)
            # return nr.homepage
            return f"https://www.npmjs.com/package/{nr.name}/v/{version}"
        case sql.DistributionPlatform.NPM_SCOPED:
            nr = NpmResponse.model_validate(data)
            # TODO: This is not correct
            return nr.homepage
        case sql.DistributionPlatform.PYPI:
            info = PyPIResponse.model_validate(data).info
            return info.release_url or info.project_url
    raise NotImplementedError(f"Platform {platform.name} is not yet supported")


async def _json_from_distribution_platform(
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


# TODO: Move this to an appropriate module
def _html_nav(container: htm.Block, back_url: str, back_anchor: str, phase: Phase) -> None:
    classes = ".d-flex.justify-content-between.align-items-center"
    block = htm.Block(htpy.p(classes))
    block.a(".atr-back-link", href=back_url)[f"← Back to {back_anchor}"]
    span = htm.Block(htpy.span)

    def _phase(actual: Phase, expected: Phase) -> None:
        nonlocal span
        match expected:
            case "COMPOSE":
                symbol = "①"
            case "VOTE":
                symbol = "②"
            case "FINISH":
                symbol = "③"
        if actual == expected:
            span.strong(f".atr-phase-{actual}.atr-phase-symbol")[symbol]
            span.span(f".atr-phase-{actual}.atr-phase-label")[actual]
        else:
            span.span(".atr-phase-symbol-other")[symbol]

    _phase(phase, "COMPOSE")
    span.span(".atr-phase-arrow")["→"]
    _phase(phase, "VOTE")
    span.span(".atr-phase-arrow")["→"]
    _phase(phase, "FINISH")

    block.append(span.collect(separator=" "))
    container.append(block)


def _html_nav_phase(block: htm.Block, project: str, version: str, staging: bool) -> None:
    label: Phase
    route, label = (compose.selected, "COMPOSE")
    if not staging:
        route, label = (finish.selected, "FINISH")
    _html_nav(
        block,
        util.as_url(
            route,
            project_name=project,
            version_name=version,
        ),
        back_anchor=f"{label.title()} {project} {version}",
        phase=label,
    )


def _html_submitted_values_table(block: htm.Block, dd: DistributeData) -> None:
    tbody = htpy.tbody[
        _html_tr("Platform", dd.platform.name),
        _html_tr("Owner or Namespace", dd.owner_namespace or "-"),
        _html_tr("Package", dd.package),
        _html_tr("Version", dd.version),
    ]
    block.table(".table.table-striped.table-bordered")[tbody]


def _html_tr(label: str, value: str) -> htpy.Element:
    return htpy.tr[htpy.th[label], htpy.td[value]]


def _html_tr_a(label: str, value: str | None) -> htpy.Element:
    return htpy.tr[htpy.th[label], htpy.td[htpy.a(href=value)[value] if value else "-"]]


# This function is used for COMPOSE (stage) and FINISH (record)
# It's also used whenever there is an error
async def _record_form_page(
    fpv: FormProjectVersion, *, extra_content: htpy.Element | None = None, staging: bool = False
) -> str:
    await _release_validated(fpv.project, fpv.version, staging=staging)

    # Render the explanation and form
    block = htm.Block()
    _html_nav_phase(block, fpv.project, fpv.version, staging)

    # Record a manual distribution
    title_and_heading = f"Record a {'staging' if staging else 'manual'} distribution"
    block.h1[title_and_heading]
    if extra_content:
        block.append(extra_content)
    block.p[
        "Record a distribution of ",
        htpy.strong[f"{fpv.project}-{fpv.version}"],
        " using the form below.",
    ]
    block.p[
        "You can also ",
        htpy.a(href=util.as_url(list_get, project=fpv.project, version=fpv.version))["view the distribution list"],
        ".",
    ]
    block.append(forms.render_columns(fpv.form, action=quart.request.path, descriptions=True))

    # Render the page
    return await template.blank(title_and_heading, content=block.collect())


async def _record_form_process_page(fpv: FormProjectVersion, /, staging: bool = False) -> str:
    dd = DistributeData.model_validate(fpv.form.data)
    resolved = await _release_validated_and_committee_and_template(fpv, dd, staging)
    if isinstance(resolved, htpy.Element):
        return await _record_form_page(fpv, extra_content=resolved, staging=staging)
    release, committee, template_url = resolved
    api_url = template_url.format(
        owner_namespace=dd.owner_namespace,
        package=dd.package,
        version=dd.version,
    )
    api_oc = await _json_from_distribution_platform(api_url, dd.platform, dd.version)

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
            pass
        case outcome.Error():
            alert = _alert("package and version", "check the package name and version")
            return await _record_form_page(fpv, extra_content=alert, staging=staging)
        # We leak result, usefully, from this scope

    # This must come after the api_oc match, as it uses the result
    upload_date = _distribution_upload_date(dd.platform, result, dd.version)
    if upload_date is None:
        # TODO: Add a link to an issue tracker
        alert = _alert("upload date", "report this bug to ASF Tooling")
        return await _record_form_page(fpv, extra_content=alert, staging=staging)

    web_url = _distribution_web_url(dd.platform, result, dd.version)
    async with storage.write_as_committee_member(committee_name=committee.name) as w:
        distribution, added = await w.distributions.add_distribution(
            release_name=release.name,
            platform=dd.platform,
            owner_namespace=dd.owner_namespace,
            package=dd.package,
            version=dd.version,
            staging=staging,
            upload_date=upload_date,
            api_url=api_url,
            web_url=web_url,
        )

    ### Record
    block.h2["Record"]
    if added:
        block.p["The distribution was recorded successfully."]
    else:
        block.p["The distribution was already recorded."]
    block.table(".table.table-striped.table-bordered")[
        htpy.tbody[
            _html_tr("Release name", distribution.release_name),
            _html_tr("Platform", distribution.platform.name),
            _html_tr("Owner or Namespace", distribution.owner_namespace or "-"),
            _html_tr("Package", distribution.package),
            _html_tr("Version", distribution.version),
            _html_tr("Staging", "Yes" if distribution.staging else "No"),
            _html_tr("Upload date", str(distribution.upload_date)),
            _html_tr_a("API URL", distribution.api_url),
            _html_tr_a("Web URL", distribution.web_url),
        ]
    ]
    block.p[htpy.a(href=util.as_url(list_get, project=fpv.project, version=fpv.version))["Back to distribution list"],]

    if dd.details:
        ## Details
        block.h2["Details"]

        ### Submitted values
        block.h3["Submitted values"]
        _html_submitted_values_table(block, dd)

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


async def _release_validated_and_committee(
    project: str,
    version: str,
    *,
    staging: bool | None = None,
) -> tuple[sql.Release, sql.Committee]:
    release = await _release_validated(project, version, committee=True, staging=staging)
    committee = release.committee
    if committee is None:
        raise RuntimeError(f"Release {project} {version} has no committee")
    return release, committee


async def _release_validated(
    project: str,
    version: str,
    committee: bool = False,
    staging: bool | None = None,
) -> sql.Release:
    match staging:
        case True:
            phase = {sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT}
        case False:
            phase = {sql.ReleasePhase.RELEASE_PREVIEW}
        case None:
            phase = {sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT, sql.ReleasePhase.RELEASE_PREVIEW}
    async with db.session() as data:
        release = await data.release(
            project_name=project,
            version=version,
            _committee=committee,
        ).demand(RuntimeError(f"Release {project} {version} not found"))
        if release.phase not in phase:
            raise RuntimeError(f"Release {project} {version} is not in {phase}")
        # if release.project.status != sql.ProjectStatus.ACTIVE:
        #     raise RuntimeError(f"Project {project} is not active")
    return release


async def _release_validated_and_committee_and_template(
    fpv: FormProjectVersion,
    dd: DistributeData,
    staging: bool | None = None,
) -> tuple[sql.Release, sql.Committee, str] | htpy.Element:
    release, committee = await _release_validated_and_committee(
        fpv.project,
        fpv.version,
        staging=staging,
    )
    if staging is False:
        return release, committee, dd.platform.value.template_url

    supported = {sql.DistributionPlatform.ARTIFACT_HUB, sql.DistributionPlatform.PYPI}
    if dd.platform not in supported:
        div = htm.Block(htpy.div(".alert.alert-danger"))
        div.p["Staging is currently supported only for ArtifactHub and PyPI."]
        return div.collect()

    template_url = dd.platform.value.template_staging_url
    if template_url is None:
        div = htm.Block(htpy.div(".alert.alert-danger"))
        div.p["This platform does not provide a staging API endpoint."]
        return div.collect()

    return release, committee, template_url
