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
import atr.db as db
import atr.forms as forms
import atr.htm as htm
import atr.models.sql as sql
import atr.post as post
import atr.shared as shared
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

    release = await shared.distribution.release_validated(project, version, staging=None)
    staging = release.phase == sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
    shared.distribution.html_nav_phase(block, project, version, staging)

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
        delete_form = await shared.distribution.DeleteForm.create_form(
            data={
                "release_name": dist.release_name,
                "platform": dist.platform.name,
                "owner_namespace": dist.owner_namespace,
                "package": dist.package,
                "version": dist.version,
            }
        )

        ### Platform package version
        block.h3(
            # Cannot use "#id" here, because the ID contains "."
            # If an ID contains ".", htm parses that as a class
            id=f"distribution-{dist.identifier}"
        )[dist.title]
        tbody = htm.tbody[
            shared.distribution.html_tr("Release name", dist.release_name),
            shared.distribution.html_tr("Platform", dist.platform.value.name),
            shared.distribution.html_tr("Owner or Namespace", dist.owner_namespace or "-"),
            shared.distribution.html_tr("Package", dist.package),
            shared.distribution.html_tr("Version", dist.version),
            shared.distribution.html_tr("Staging", "Yes" if dist.staging else "No"),
            shared.distribution.html_tr("Upload date", str(dist.upload_date)),
            shared.distribution.html_tr_a("API URL", dist.api_url),
            shared.distribution.html_tr_a("Web URL", dist.web_url),
        ]
        block.table(".table.table-striped.table-bordered")[tbody]
        form_action = util.as_url(post.distribution.delete, project=project, version=version)
        delete_form_element = forms.render_simple(
            delete_form,
            action=form_action,
            submit_classes="btn-danger",
        )
        block.append(htm.div(".mb-3")[delete_form_element])

    title = f"Distribution list for {project} {version}"
    return await template.blank(title, content=block.collect())


@get.committer("/distribution/record/<project>/<version>")
async def record(session: web.Committer, project: str, version: str) -> str:
    form = await shared.distribution.DistributeForm.create_form(data={"package": project, "version": version})
    fpv = shared.distribution.FormProjectVersion(form=form, project=project, version=version)
    return await shared.distribution.record_form_page(fpv)


@get.committer("/distribution/stage/<project>/<version>")
async def stage(session: web.Committer, project: str, version: str) -> str:
    form = await shared.distribution.DistributeForm.create_form(data={"package": project, "version": version})
    fpv = shared.distribution.FormProjectVersion(form=form, project=project, version=version)
    return await shared.distribution.record_form_page(fpv, staging=True)
