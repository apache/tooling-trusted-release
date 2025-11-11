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
import atr.htm as htm
import atr.log as log
import atr.models.sql as sql
import atr.shared as shared
import atr.storage as storage
import atr.storage.outcome as outcome
import atr.storage.types as types
import atr.util as util
import atr.web as web


@post.committer("/keys/add")
@post.form(shared.keys.AddOpenPGPKeyForm)
async def add(session: web.Committer, add_openpgp_key_form: shared.keys.AddOpenPGPKeyForm) -> web.WerkzeugResponse:
    """Add a new public signing key to the user's account."""
    try:
        key_text = add_openpgp_key_form.public_key
        selected_committee_names = add_openpgp_key_form.selected_committees

        async with storage.write() as write:
            wafc = write.as_foundation_committer()
            ocr: outcome.Outcome[types.Key] = await wafc.keys.ensure_stored_one(key_text)
            key = ocr.result_or_raise()

            for selected_committee_name in selected_committee_names:
                wacp = write.as_committee_participant(selected_committee_name)
                oc: outcome.Outcome[types.LinkedCommittee] = await wacp.keys.associate_fingerprint(
                    key.key_model.fingerprint
                )
                oc.result_or_raise()

            fingerprint_upper = key.key_model.fingerprint.upper()
            if key.status == types.KeyStatus.PARSED:
                details_url = util.as_url(get.keys.details, fingerprint=key.key_model.fingerprint)
                p = htm.p[
                    f"OpenPGP key {fingerprint_upper} was already in the database. ",
                    htm.a(href=details_url)["View key details"],
                    ".",
                ]
                await quart.flash(str(p), "warning")
            else:
                await quart.flash(f"OpenPGP key {fingerprint_upper} added successfully.", "success")

    except web.FlashError as e:
        log.warning("FlashError adding OpenPGP key: %s", e)
        await quart.flash(str(e), "error")
    except Exception as e:
        log.exception("Error adding OpenPGP key:")
        await quart.flash(f"An unexpected error occurred: {e!s}", "error")

    return await session.redirect(get.keys.keys)


@post.committer("/keys")
@post.form(shared.keys.KeysForm)
async def keys(session: web.Committer, keys_form: shared.keys.KeysForm) -> web.WerkzeugResponse:
    """Handle forms on the keys management page."""
    match keys_form:
        case shared.keys.DeleteOpenPGPKeyForm() as delete_openpgp_form:
            return await _delete_openpgp_key(session, delete_openpgp_form)

        case shared.keys.DeleteSSHKeyForm() as delete_ssh_form:
            return await _delete_ssh_key(session, delete_ssh_form)

        case shared.keys.UpdateCommitteeKeysForm() as update_committee_form:
            return await _update_committee_keys(session, update_committee_form)


async def _delete_openpgp_key(
    session: web.Committer, delete_form: shared.keys.DeleteOpenPGPKeyForm
) -> web.WerkzeugResponse:
    """Delete an OpenPGP key from the user's account."""
    fingerprint = delete_form.fingerprint

    async with storage.write() as write:
        wafc = write.as_foundation_committer()
        oc: outcome.Outcome[sql.PublicSigningKey] = await wafc.keys.delete_key(fingerprint)

    match oc:
        case outcome.Result():
            return await session.redirect(get.keys.keys, success="OpenPGP key deleted successfully")
        case outcome.Error(error):
            return await session.redirect(get.keys.keys, error=f"Error deleting OpenPGP key: {error}")


async def _delete_ssh_key(session: web.Committer, delete_form: shared.keys.DeleteSSHKeyForm) -> web.WerkzeugResponse:
    """Delete an SSH key from the user's account."""
    fingerprint = delete_form.fingerprint

    async with storage.write() as write:
        wafc = write.as_foundation_committer()
        try:
            await wafc.ssh.delete_key(fingerprint)
        except storage.AccessError as e:
            return await session.redirect(get.keys.keys, error=f"Error deleting SSH key: {e}")

    return await session.redirect(get.keys.keys, success="SSH key deleted successfully")


async def _update_committee_keys(
    session: web.Committer, update_form: shared.keys.UpdateCommitteeKeysForm
) -> web.WerkzeugResponse:
    """Regenerate the KEYS file for a committee."""
    committee_name = update_form.committee_name

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
@post.form(shared.keys.AddSSHKeyForm)
async def ssh_add(session: web.Committer, add_ssh_key_form: shared.keys.AddSSHKeyForm) -> web.WerkzeugResponse:
    """Add a new SSH key to the user's account."""
    try:
        async with storage.write(session) as write:
            wafc = write.as_foundation_committer()
            fingerprint = await wafc.ssh.add_key(add_ssh_key_form.key, session.uid)

        await quart.flash(f"SSH key added successfully: {fingerprint}", "success")
    except util.SshFingerprintError as e:
        await quart.flash(str(e), "error")
    except Exception as e:
        log.exception("Error adding SSH key:")
        await quart.flash(f"An unexpected error occurred: {e!s}", "error")

    return await session.redirect(get.keys.keys)


@post.committer("/keys/upload")
async def upload(session: web.Committer) -> str:
    """Upload a KEYS file containing multiple OpenPGP keys."""
    return await shared.keys.upload(session)
