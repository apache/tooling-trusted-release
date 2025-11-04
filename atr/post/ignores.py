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

import atr.blueprints.post as post
import atr.get as get
import atr.models.sql as sql
import atr.shared as shared
import atr.storage as storage
import atr.web as web


@post.committer("/ignores/<committee_name>/add")
async def ignores_committee_add(session: web.Committer, committee_name: str) -> str | web.WerkzeugResponse:
    data = await quart.request.form
    form = await shared.ignores.AddIgnoreForm.create_form(data=data)
    if not (await form.validate_on_submit()):
        return await session.redirect(get.ignores.ignores, error="Form validation errors")

    status = sql.CheckResultStatusIgnore.from_form_field(form.status.data)

    async with storage.write() as write:
        wacm = write.as_committee_member(committee_name)
        await wacm.checks.ignore_add(
            release_glob=form.release_glob.data or None,
            revision_number=form.revision_number.data or None,
            checker_glob=form.checker_glob.data or None,
            primary_rel_path_glob=form.primary_rel_path_glob.data or None,
            member_rel_path_glob=form.member_rel_path_glob.data or None,
            status=status,
            message_glob=form.message_glob.data or None,
        )

    return await session.redirect(
        get.ignores.ignores,
        committee_name=committee_name,
        success="Ignore added",
    )


@post.committer("/ignores/<committee_name>/delete")
async def ignores_committee_delete(session: web.Committer, committee_name: str) -> str | web.WerkzeugResponse:
    data = await quart.request.form
    form = await shared.ignores.DeleteIgnoreForm.create_form(data=data)
    if not (await form.validate_on_submit()):
        return await session.redirect(
            get.ignores.ignores,
            committee_name=committee_name,
            error="Form validation errors",
        )

    if not isinstance(form.id.data, str):
        return await session.redirect(
            get.ignores.ignores,
            committee_name=committee_name,
            error="Invalid ignore ID",
        )

    cri_id = int(form.id.data)
    async with storage.write() as write:
        wacm = write.as_committee_member(committee_name)
        await wacm.checks.ignore_delete(id=cri_id)

    return await session.redirect(
        get.ignores.ignores,
        committee_name=committee_name,
        success="Ignore deleted",
    )


@post.committer("/ignores/<committee_name>/update")
async def ignores_committee_update(session: web.Committer, committee_name: str) -> str | web.WerkzeugResponse:
    data = await quart.request.form
    form = await shared.ignores.UpdateIgnoreForm.create_form(data=data)
    if not (await form.validate_on_submit()):
        return await session.redirect(get.ignores.ignores, error="Form validation errors")

    status = sql.CheckResultStatusIgnore.from_form_field(form.status.data)
    if not isinstance(form.id.data, str):
        return await session.redirect(
            get.ignores.ignores,
            committee_name=committee_name,
            error="Invalid ignore ID",
        )
    cri_id = int(form.id.data)

    async with storage.write() as write:
        wacm = write.as_committee_member(committee_name)
        await wacm.checks.ignore_update(
            id=cri_id,
            release_glob=form.release_glob.data or None,
            revision_number=form.revision_number.data or None,
            checker_glob=form.checker_glob.data or None,
            primary_rel_path_glob=form.primary_rel_path_glob.data or None,
            member_rel_path_glob=form.member_rel_path_glob.data or None,
            status=status,
            message_glob=form.message_glob.data or None,
        )

    return await session.redirect(
        get.ignores.ignores,
        committee_name=committee_name,
        success="Ignore updated",
    )
