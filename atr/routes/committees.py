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

"""project.py"""

import datetime
import http.client

import atr.db as db
import atr.forms as forms
import atr.models.sql as sql
import atr.routes as routes
import atr.template as template
import atr.util as util


class UpdateCommitteeKeysForm(forms.Typed):
    submit = forms.submit("Regenerate KEYS file")


@routes.public("/committees")
async def directory() -> str:
    """Main committee directory page."""
    async with db.session() as data:
        committees = await data.committee(_projects=True).order_by(sql.Committee.name).all()
        return await template.render(
            "committee-directory.html",
            committees=committees,
            committee_is_standing=util.committee_is_standing,
        )


@routes.public("/committees/<name>")
async def view(name: str) -> str:
    # TODO: Could also import this from keys.py
    async with db.session() as data:
        committee = await data.committee(
            name=name,
            _projects=True,
            _public_signing_keys=True,
        ).demand(http.client.HTTPException(404))
    project_list = list(committee.projects)
    for project in project_list:
        # Workaround for the usual loading problem
        project.committee = committee
    return await template.render(
        "committee-view.html",
        committee=committee,
        projects=project_list,
        algorithms=routes.algorithms,
        now=datetime.datetime.now(datetime.UTC),
        email_from_key=util.email_from_uid,
        update_committee_keys_form=await UpdateCommitteeKeysForm.create_form(),
    )
