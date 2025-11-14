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
import htpy

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

        # Create inline delete form with confirmation dialog (following projects.py pattern)
        delete_form = htm.form(
            ".d-inline-block.m-0",
            method="post",
            action=util.as_url(post.distribution.delete, project=project, version=version),
            onsubmit=(
                f"return confirm('Are you sure you want to delete the distribution "
                f"{dist.platform.name} {dist.package} {dist.version}? This cannot be undone.');"
            ),
        )[
            form.csrf_input(),
            htpy.input(type="hidden", name="release_name", value=dist.release_name),
            htpy.input(type="hidden", name="platform", value=dist.platform.name),
            htpy.input(type="hidden", name="owner_namespace", value=dist.owner_namespace or ""),
            htpy.input(type="hidden", name="package", value=dist.package),
            htpy.input(type="hidden", name="version", value=dist.version),
            htpy.button(
                ".btn.btn-danger.btn-sm",
                type="submit",
                title=f"Delete {dist.title}"
            )[
                htpy.i(".bi.bi-trash"), " Delete"
            ],
        ]
        block.append(htm.div(".mb-3")[delete_form])

    title = f"Distribution list for {project} {version}"
    return await template.blank(title, content=block.collect())


# The delete_get function can now be removed since we're using inline confirmation
# But if you want to keep it for direct URL access, you can redirect to the list
@get.committer("/distribution/delete/<project>/<version>")
async def delete_get(session: web.Committer, project: str, version: str) -> web.WerkzeugResponse:
    # Redirect to the list page instead of showing a separate confirmation page
    return await session.redirect(list_get, project=project, version=version)


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
