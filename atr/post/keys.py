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


import asfquart as asfquart
import quart

import atr.blueprints.post as post
import atr.get as get
import atr.models.sql as sql
import atr.shared as shared
import atr.storage as storage
import atr.storage.outcome as outcome
import atr.storage.types as types
import atr.util as util
import atr.web as web


@post.committer("/keys/add")
async def add(session: web.Committer) -> str:
    """Add a new public signing key to the user's account."""
    return await shared.keys.add(session)


@post.committer("/keys/delete")
async def delete(session: web.Committer) -> web.WerkzeugResponse:
    """Delete a public signing key or SSH key from the user's account."""
    form = await shared.keys.DeleteKeyForm.create_form(data=await quart.request.form)

    if not await form.validate_on_submit():
        return await session.redirect(get.keys.keys, error="Invalid request for key deletion.")

    fingerprint = (await quart.request.form).get("fingerprint")
    if not fingerprint:
        return await session.redirect(get.keys.keys, error="Missing key fingerprint for deletion.")

    # Try to delete an SSH key first
    # Otherwise, delete an OpenPGP key
    # TODO: Unmerge this, or identify the key type
    async with storage.write() as write:
        wafc = write.as_foundation_committer()
        try:
            await wafc.ssh.delete_key(fingerprint)
        except storage.AccessError:
            pass
        else:
            return await session.redirect(get.keys.keys, success="SSH key deleted successfully")
        oc: outcome.Outcome[sql.PublicSigningKey] = await wafc.keys.delete_key(fingerprint)

    match oc:
        case outcome.Result():
            return await session.redirect(get.keys.keys, success="Key deleted successfully")
        case outcome.Error(error):
            return await session.redirect(get.keys.keys, error=f"Error deleting key: {error}")


@post.committer("/keys/details/<fingerprint>")
async def details(session: web.Committer, fingerprint: str) -> str | web.WerkzeugResponse:
    """Display details for a specific OpenPGP key."""
    return await shared.keys.details(session, fingerprint)


@post.committer("/keys/import/<project_name>/<version_name>")
async def import_selected_revision(
    session: web.Committer, project_name: str, version_name: str
) -> web.WerkzeugResponse:
    await util.validate_empty_form()

    async with storage.write() as write:
        wacm = await write.as_project_committee_member(project_name)
        outcomes: outcome.List[types.Key] = await wacm.keys.import_keys_file(project_name, version_name)

    message = f"Uploaded {outcomes.result_count} keys,"
    if outcomes.error_count > 0:
        message += f" failed to upload {outcomes.error_count} keys for {wacm.committee_name}"
    return await session.redirect(
        get.compose.selected,
        success=message,
        project_name=project_name,
        version_name=version_name,
    )


@post.committer("/keys/ssh/add")
async def ssh_add(session: web.Committer) -> web.WerkzeugResponse | str:
    """Add a new SSH key to the user's account."""
    return await shared.keys.ssh_add(session)


@post.committer("/keys/update-committee-keys/<committee_name>")
async def update_committee_keys(session: web.Committer, committee_name: str) -> web.WerkzeugResponse:
    """Generate and save the KEYS file for a specific committee."""
    form = await shared.keys.UpdateCommitteeKeysForm.create_form()
    if not await form.validate_on_submit():
        return await session.redirect(get.keys.keys, error="Invalid request to update KEYS file.")

    async with storage.write() as write:
        wacm = write.as_committee_member(committee_name)
        match await wacm.keys.autogenerate_keys_file():
            case outcome.Result():
                await quart.flash(
                    f'Successfully regenerated the KEYS file for the "{committee_name}" committee.', "success"
                )
            case outcome.Error():
                await quart.flash(f"Error regenerating the KEYS file for the {committee_name} committee.", "error")

    return await session.redirect(get.keys.keys)


@post.committer("/keys/upload")
async def upload(session: web.Committer) -> str:
    """Upload a KEYS file containing multiple OpenPGP keys."""
    return await shared.keys.upload(session)
