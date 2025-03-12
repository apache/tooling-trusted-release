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

"""vote_policy.py"""

import quart
import quart_wtf
import sqlmodel
import werkzeug.wrappers.response as response
import wtforms

import asfquart.session as session
import atr.db as db
import atr.db.models as models
import atr.routes as routes
from asfquart import base
from asfquart.base import ASFQuartException


class VotePolicyForm(quart_wtf.QuartForm):
    project_name = wtforms.HiddenField("project_name")
    mailto_addresses = wtforms.StringField(
        "Email",
        validators=[
            wtforms.validators.InputRequired("Please provide a valid email address"),
            wtforms.validators.Email(),
        ],
    )
    min_hours = wtforms.IntegerField(
        "Minimum Voting Period:", widget=wtforms.widgets.NumberInput(min=0, max=144), default=72
    )
    manual_vote = wtforms.BooleanField("Voting Process:")
    release_checklist = wtforms.StringField("Release Checklist:", widget=wtforms.widgets.TextArea())
    pause_for_rm = wtforms.BooleanField("Pause for RM:")

    submit = wtforms.SubmitField("Save")


@routes.app_route("/vote/<vote_policy_id>/edit", methods=["GET", "POST"])
async def root_vote_policy_edit(vote_policy_id: str) -> response.Response | str:
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    async with db.create_async_db_session() as db_session:
        statement = sqlmodel.select(models.VotePolicy).where(models.VotePolicy.id == int(vote_policy_id))
        vote_policy = (await db_session.execute(statement)).scalar_one_or_none()
        if not vote_policy:
            raise ASFQuartException("Vote policy not found", 404)

    form = await VotePolicyForm.create_form()

    if quart.request.method == "GET":
        form.process(obj=vote_policy)

    if await form.validate_on_submit():
        return ""
        # return await add_voting_policy(web_session, form)  # pyright: ignore [reportArgumentType]

    # For GET requests, show the form
    return await quart.render_template(
        "vote-policy-edit.html",
        asf_id=web_session.uid,
        form=form,
    )


# async def add_voting_policy(session: session.ClientSession, form: CreateVotePolicyForm) -> response.Response:
#     project_name = form.project_name.data
#
#     async with db.create_async_db_session() as db_session:
#         async with db_session.begin():
#             statement = sqlmodel.select(models.PMC).where(models.PMC.project_name == project_name)
#             pmc = (await db_session.execute(statement)).scalar_one_or_none()
#             if not pmc:
#                 raise base.ASFQuartException("PMC not found", errorcode=404)
#             elif pmc.project_name not in session.committees:
#                 raise base.ASFQuartException(
#                     f"You must be a PMC member of {pmc.display_name} to submit a voting policy", errorcode=403
#                 )
#
#             vote_policy = models.VotePolicy(
#                 mailto_addresses=[unwrap(form.mailto_addresses.data)],
#                 manual_vote=form.manual_vote.data,
#                 min_hours=unwrap(form.min_hours.data),
#                 release_checklist=unwrap(form.release_checklist.data),
#                 pause_for_rm=form.pause_for_rm.data,
#             )
#             db_session.add(vote_policy)
#
#     # Redirect to the add package page with the storage token
#     return quart.redirect(quart.url_for("root_project_view", project_name=project_name))
