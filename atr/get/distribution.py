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

import quart

import atr.blueprints.get as get
import atr.db as db
import atr.form as form
import atr.htm as htm
import atr.models.sql as sql
import atr.post as post
import atr.shared.distribution as shared
import atr.template as template
import atr.util as util
import atr.web as web


@get.committer("/distributions/list/<project>/<version>")
async def list_get(session: web.Committer, project: str, version: str) -> str:
    async with db.session() as data:
        distributions = await data.distribution(
            release_name=sql.release_name(project, version),
        ).all()

    block = htm.Block()

    release = await shared.release_validated(project, version, staging=None)
    staging = release.phase == sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
    shared.html_nav_phase(block, project, version, staging)

    record_a_distribution = htm.a(
        ".btn.btn-primary",
        href=util.as_url(
            stage if staging else record,
            project=project,
            version=version,
        ),
    )["Record a distribution"]

    # Distribution list for project-version
    block.h1["Distribution list for ", htm.em[f"{project}-{version}"]]
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
    block.append(htm.ul_links(*[(f"#distribution-{dist.identifier}", dist.title) for dist in distributions]))

    ## Distributions
    block.h2["Distributions"]
    for dist in distributions:
        ### Platform package version
        block.h3(
            # Cannot use "#id" here, because the ID contains "."
            # If an ID contains ".", htm parses that as a class
            id=f"distribution-{dist.identifier}"
        )[dist.title]
        tbody = htm.tbody[
            shared.html_tr("Release name", dist.release_name),
            shared.html_tr("Platform", dist.platform.value.name),
            shared.html_tr("Owner or Namespace", dist.owner_namespace or "-"),
            shared.html_tr("Package", dist.package),
            shared.html_tr("Version", dist.version),
            shared.html_tr("Staging", "Yes" if dist.staging else "No"),
            shared.html_tr("Upload date", str(dist.upload_date)),
            shared.html_tr_a("API URL", dist.api_url),
            shared.html_tr_a("Web URL", dist.web_url),
        ]
        block.table(".table.table-striped.table-bordered")[tbody]

        # Create delete link (will go to delete confirmation page)
        delete_params = {
            "release_name": dist.release_name,
            "platform": dist.platform.name,
            "owner_namespace": dist.owner_namespace or "",
            "package": dist.package,
            "version": dist.version,
        }
        delete_url = util.as_url(delete_get, project=project, version=version, **delete_params)
        delete_link = htm.a(".btn.btn-danger.btn-sm", href=delete_url)["Delete"]
        block.append(htm.div(".mb-3")[delete_link])

    title = f"Distribution list for {project} {version}"
    return await template.blank(title, content=block.collect())


@get.committer("/distribution/delete/<project>/<version>")
async def delete_get(session: web.Committer, project: str, version: str) -> str:
    await shared.release_validated(project, version, staging=None)

    # Get distribution details from query params
    release_name = quart.request.args.get("release_name", "")
    platform = quart.request.args.get("platform", "")
    owner_namespace = quart.request.args.get("owner_namespace", "")
    package = quart.request.args.get("package", "")
    dist_version = quart.request.args.get("version", "")

    block = htm.Block()

    # Navigation
    release = await shared.release_validated(project, version, staging=None)
    staging = release.phase == sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
    shared.html_nav_phase(block, project, version, staging)

    # Confirmation page
    block.h1["Delete distribution"]
    block.div(".alert.alert-warning")[
        "Are you sure you want to delete this distribution? This action cannot be undone."
    ]

    # Show distribution details
    block.h3["Distribution details"]
    tbody = htm.tbody[
        shared.html_tr("Release name", release_name),
        shared.html_tr("Platform", platform),
        shared.html_tr("Owner or Namespace", owner_namespace or "-"),
        shared.html_tr("Package", package),
        shared.html_tr("Version", dist_version),
    ]
    block.table(".table.table-striped.table-bordered")[tbody]

    # Delete form with hidden fields
    delete_form = form.render(
        model_cls=shared.DeleteForm,
        submit_label="Delete Distribution",
        action=util.as_url(post.distribution.delete, project=project, version=version),
        submit_classes="btn-danger",
        cancel_url=util.as_url(list_get, project=project, version=version),
        defaults={
            "release_name": release_name,
            "platform": platform,
            "owner_namespace": owner_namespace,
            "package": package,
            "version": dist_version,
        },
    )
    block.append(delete_form)

    return await template.blank("Delete Distribution", content=block.collect())


@get.committer("/distribution/record/<project>/<version>")
async def record(session: web.Committer, project: str, version: str) -> str:
    await shared.release_validated(project, version, staging=False)

    block = htm.Block()
    shared.html_nav_phase(block, project, version, staging=False)

    block.h1["Record a manual distribution"]
    block.p[
        "Record a distribution of ",
        htm.strong[f"{project}-{version}"],
        " using the form below.",
    ]
    block.p[
        "You can also ",
        htm.a(href=util.as_url(list_get, project=project, version=version))["view the distribution list"],
        ".",
    ]

    # Render the distribution form
    form_html = form.render(
        model_cls=shared.DistributeForm,
        submit_label="Record distribution",
        action=util.as_url(post.distribution.record_post, project=project, version=version),
        defaults={"package": project, "version": version},
    )
    block.append(form_html)

    return await template.blank("Record Manual Distribution", content=block.collect())


@get.committer("/distribution/stage/<project>/<version>")
async def stage(session: web.Committer, project: str, version: str) -> str:
    await shared.release_validated(project, version, staging=True)

    block = htm.Block()
    shared.html_nav_phase(block, project, version, staging=True)

    block.h1["Record a staging distribution"]
    block.p[
        "Record a distribution of ",
        htm.strong[f"{project}-{version}"],
        " using the form below.",
    ]
    block.p[
        "You can also ",
        htm.a(href=util.as_url(list_get, project=project, version=version))["view the distribution list"],
        ".",
    ]

    # Render the distribution form
    form_html = form.render(
        model_cls=shared.DistributeForm,
        submit_label="Record distribution",
        action=util.as_url(post.distribution.stage_post, project=project, version=version),
        defaults={"package": project, "version": version},
    )
    block.append(form_html)

    return await template.blank("Record Staging Distribution", content=block.collect())
