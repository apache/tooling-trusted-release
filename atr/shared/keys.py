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

"""keys.py"""

import asyncio
import datetime
from collections.abc import Awaitable, Callable, Sequence

import aiohttp
import asfquart as asfquart
import asfquart.base as base
import quart
import werkzeug.datastructures as datastructures
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.forms as forms
import atr.get as get
import atr.log as log
import atr.models.sql as sql
import atr.shared as shared
import atr.storage as storage
import atr.storage.outcome as outcome
import atr.storage.types as types
import atr.template as template
import atr.user as user
import atr.util as util
import atr.web as web


class AddOpenPGPKeyForm(forms.Typed):
    public_key = forms.textarea(
        "Public OpenPGP key",
        placeholder="Paste your ASCII-armored public OpenPGP key here...",
        description="Your public key should be in ASCII-armored format, starting with"
        ' "-----BEGIN PGP PUBLIC KEY BLOCK-----"',
    )
    selected_committees = forms.checkboxes(
        "Associate key with committees",
        description="Select the committees with which to associate your key.",
    )
    submit = forms.submit("Add OpenPGP key")


class AddSSHKeyForm(forms.Typed):
    key = forms.textarea(
        "SSH public key",
        placeholder="Paste your SSH public key here (in the format used in authorized_keys files)",
        description=(
            "Your SSH public key should be in the standard format, starting with a key type"
            ' (like "ssh-rsa" or "ssh-ed25519") followed by the key data.'
        ),
    )

    submit = forms.submit("Add SSH key")


class DeleteKeyForm(forms.Typed):
    submit = forms.submit("Delete key")


class UpdateCommitteeKeysForm(forms.Typed):
    submit = forms.submit("Regenerate KEYS file")


class UpdateKeyCommitteesForm(forms.Typed):
    selected_committees = forms.multiple(
        "Associated PMCs",
        description="Select the committees associated with this key.",
    )
    submit = forms.submit("Update associations")


class UploadKeyFormBase(forms.Typed):
    key = forms.file(
        "KEYS file",
        optional=True,
        description=(
            "Upload a KEYS file containing multiple PGP public keys."
            " The file should contain keys in ASCII-armored format, starting with"
            ' "-----BEGIN PGP PUBLIC KEY BLOCK-----".'
        ),
    )
    keys_url = forms.url(
        "KEYS file URL",
        optional=True,
        placeholder="Enter URL to KEYS file",
        description="Enter a URL to a KEYS file. This will be fetched by the server.",
    )

    selected_committee = forms.radio(
        "Associate keys with committee",
        description=(
            "Select the committee with which to associate these keys. You must be a member of the selected committee."
        ),
    )

    submit = forms.submit("Upload KEYS file")

    async def validate(self, extra_validators: dict | None = None) -> bool:
        """Ensure that either a file is uploaded or a URL is provided, but not both."""
        if not await super().validate(extra_validators):
            return False
        if not self.key.data and not self.keys_url.data:
            msg = "Either a file or a URL is required."
            if self.key.errors and isinstance(self.key.errors, list):
                self.key.errors.append(msg)
            else:
                self.key.errors = [msg]
            return False
        if self.key.data and self.keys_url.data:
            msg = "Provide either a file or a URL, not both."
            if self.key.errors and isinstance(self.key.errors, list):
                self.key.errors.append(msg)
            else:
                self.key.errors = [msg]
            return False
        return True


async def add(session: web.Committer) -> str:
    """Add a new public signing key to the user's account."""
    key_info = None

    async with storage.write() as write:
        participant_of_committees = await write.participant_of_committees()

    committee_choices: forms.Choices = [(c.name, c.display_name or c.name) for c in participant_of_committees]

    form = await AddOpenPGPKeyForm.create_form(
        data=(await quart.request.form) if (quart.request.method == "POST") else None
    )
    forms.choices(form.selected_committees, committee_choices)

    if await form.validate_on_submit():
        try:
            key_text: str = util.unwrap(form.public_key.data)
            selected_committee_names: list[str] = util.unwrap(form.selected_committees.data)

            async with storage.write() as write:
                wafc = write.as_foundation_committer()
                ocr: outcome.Outcome[types.Key] = await wafc.keys.ensure_stored_one(key_text)
                key = ocr.result_or_raise()

                for selected_committee_name in selected_committee_names:
                    # TODO: Should this be committee member or committee participant?
                    # Also, should we emit warnings and continue here?
                    wacp = write.as_committee_participant(selected_committee_name)
                    oc: outcome.Outcome[types.LinkedCommittee] = await wacp.keys.associate_fingerprint(
                        key.key_model.fingerprint
                    )
                    oc.result_or_raise()

                await quart.flash(f"OpenPGP key {key.key_model.fingerprint.upper()} added successfully.", "success")
            # Clear form data on success by creating a new empty form instance
            form = await AddOpenPGPKeyForm.create_form()
            forms.choices(form.selected_committees, committee_choices)

        except web.FlashError as e:
            log.warning("FlashError adding OpenPGP key: %s", e)
            await quart.flash(str(e), "error")
        except Exception as e:
            log.exception("Error adding OpenPGP key:")
            await quart.flash(f"An unexpected error occurred: {e!s}", "error")

    return await template.render(
        "keys-add.html",
        asf_id=session.uid,
        user_committees=participant_of_committees,
        form=form,
        key_info=key_info,
        algorithms=shared.algorithms,
    )


async def details(session: web.Committer, fingerprint: str) -> str | response.Response:
    """Display details for a specific OpenPGP key."""
    fingerprint = fingerprint.lower()
    user_committees = []
    async with db.session() as data:
        key, is_owner = await _key_and_is_owner(data, session, fingerprint)
        form = None
        if is_owner:
            project_list = session.committees + session.projects
            user_committees = await data.committee(name_in=project_list).all()
    if is_owner:
        committee_choices: forms.Choices = [(c.name, c.display_name or c.name) for c in user_committees]

        # TODO: Probably need to do data in a separate phase
        form = await UpdateKeyCommitteesForm.create_form(
            data=await quart.request.form if (quart.request.method == "POST") else None
        )
        forms.choices(form.selected_committees, committee_choices)

    if form and await form.validate_on_submit():
        async with db.session() as data:
            key = await data.public_signing_key(fingerprint=fingerprint, _committees=True).get()
            if not key:
                quart.abort(404, description="OpenPGP key not found")

            selected_committee_names = form.selected_committees.data or []
            old_committee_names = {c.name for c in key.committees}

            new_committees = await data.committee(name_in=selected_committee_names).all()
            key.committees = list(new_committees)
            data.add(key)
            await data.commit()

            affected_committee_names = old_committee_names.union(set(selected_committee_names))
            if affected_committee_names:
                async with storage.write() as write:
                    for affected_committee_name in affected_committee_names:
                        wacm = write.as_committee_member_outcome(affected_committee_name).result_or_none()
                        if wacm is None:
                            continue
                        await wacm.keys.autogenerate_keys_file()

            await quart.flash("Key committee associations updated successfully.", "success")
            return await session.redirect(details, fingerprint=fingerprint)

    if isinstance(key.ascii_armored_key, bytes):
        key.ascii_armored_key = key.ascii_armored_key.decode("utf-8", errors="replace")

    return await template.render(
        "keys-details.html",
        key=key,
        form=form,
        algorithms=shared.algorithms,
        now=datetime.datetime.now(datetime.UTC),
        asf_id=session.uid,
    )


async def ssh_add(session: web.Committer) -> response.Response | str:
    """Add a new SSH key to the user's account."""
    # TODO: Make an auth.require wrapper that gives the session automatically
    # And the form if it's a POST handler? Might be hard to type
    # But we can use variants of the function
    # GET, POST, GET_POST are all we need
    # We could even include auth in the function names
    form = await AddSSHKeyForm.create_form()
    fingerprint = None
    if await form.validate_on_submit():
        key: str = util.unwrap(form.key.data)
        try:
            async with storage.write(session) as write:
                wafc = write.as_foundation_committer()
                fingerprint = await wafc.ssh.add_key(key, session.uid)
        except util.SshFingerprintError as e:
            if isinstance(form.key.errors, list):
                form.key.errors.append(str(e))
            else:
                form.key.errors = [str(e)]
        else:
            success_message = f"SSH key added successfully: {fingerprint}"
            return await session.redirect(get.keys.keys, success=success_message)

    return await template.render(
        "keys-ssh-add.html",
        asf_id=session.uid,
        form=form,
        fingerprint=fingerprint,
    )


async def upload(session: web.Committer) -> str:
    """Upload a KEYS file containing multiple OpenPGP keys."""
    async with storage.write() as write:
        participant_of_committees = await write.participant_of_committees()

    # TODO: Migrate to the forms interface
    class UploadKeyForm(UploadKeyFormBase):
        selected_committee = wtforms.SelectField(
            "Associate keys with committee",
            choices=[
                (c.name, c.display_name)
                for c in participant_of_committees
                if (not util.committee_is_standing(c.name)) or (c.name == "tooling")
            ],
            coerce=str,
            option_widget=wtforms.widgets.RadioInput(),
            widget=wtforms.widgets.ListWidget(prefix_label=False),
            validators=[wtforms.validators.InputRequired("You must select at least one committee")],
            description=("Select the committee with which to associate these keys."),
        )

    form = await UploadKeyForm.create_form()
    results: outcome.List[types.Key] | None = None

    async def render(
        error: str | None = None,
        submitted_committees: list[str] | None = None,
        all_user_committees: Sequence[sql.Committee] | None = None,
    ) -> str:
        # For easier happy pathing
        if error is not None:
            await quart.flash(error, "error")

        # Determine which committee list to use
        current_committees = all_user_committees if (all_user_committees is not None) else participant_of_committees
        committee_map = {c.name: c.display_name for c in current_committees}

        return await template.render(
            "keys-upload.html",
            asf_id=session.uid,
            user_committees=current_committees,
            committee_map=committee_map,
            form=form,
            results=results,
            algorithms=shared.algorithms,
            submitted_committees=submitted_committees,
        )

    if await form.validate_on_submit():
        keys_text = ""
        if form.key.data:
            key_file = form.key.data
            if not isinstance(key_file, datastructures.FileStorage):
                return await render(error="Invalid file upload")
            keys_content = await asyncio.to_thread(key_file.read)
            keys_text = keys_content.decode("utf-8", errors="replace")
        elif form.keys_url.data:
            keys_text = await _get_keys_text(form.keys_url.data, render)

        if not keys_text:
            return await render(error="No KEYS data found.")

        # Get selected committee list from the form
        selected_committee = form.selected_committee.data
        if not selected_committee:
            return await render(error="You must select at least one committee")

        async with storage.write() as write:
            wacp = write.as_committee_participant(selected_committee)
            outcomes = await wacp.keys.ensure_associated(keys_text)
        results = outcomes
        success_count = outcomes.result_count
        error_count = outcomes.error_count
        total_count = success_count + error_count

        await quart.flash(
            f"Processed {total_count} keys: {success_count} successful, {error_count} failed",
            "success" if success_count > 0 else "error",
        )
        return await render(
            submitted_committees=[selected_committee],
            all_user_committees=participant_of_committees,
        )

    return await render()


async def _get_keys_text(keys_url: str, render: Callable[[str], Awaitable[str]]) -> str:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(keys_url, allow_redirects=True) as response:
                response.raise_for_status()
                return await response.text()
    except aiohttp.ClientResponseError as e:
        raise base.ASFQuartException(f"Unable to fetch keys from remote server: {e.status} {e.message}", errorcode=502)
    except aiohttp.ClientError as e:
        raise base.ASFQuartException(f"Network error while fetching keys: {e}", errorcode=503)


async def _key_and_is_owner(
    data: db.Session, session: web.Committer, fingerprint: str
) -> tuple[sql.PublicSigningKey, bool]:
    key = await data.public_signing_key(fingerprint=fingerprint, _committees=True).get()
    if not key:
        quart.abort(404, description="OpenPGP key not found")
    key.committees.sort(key=lambda c: c.name)

    # Allow owners and committee members to view the key
    authorised = False
    is_owner = False
    if key.apache_uid and session.uid:
        is_owner = key.apache_uid.lower() == session.uid.lower()
    if is_owner:
        authorised = True
    else:
        user_affiliations = set(session.committees + session.projects)
        key_committee_names = {c.name for c in key.committees}
        if user_affiliations.intersection(key_committee_names):
            authorised = True
        elif user.is_admin(session.uid):
            authorised = True

    if not authorised:
        quart.abort(403, description="You are not authorised to view this key")

    return key, is_owner
