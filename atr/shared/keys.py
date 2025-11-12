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
from collections.abc import Awaitable, Callable, Sequence
from typing import Annotated, Literal

import aiohttp
import asfquart.base as base
import pydantic
import quart
import werkzeug.datastructures as datastructures
import wtforms

import atr.form as form
import atr.forms as forms
import atr.models.sql as sql
import atr.shared as shared
import atr.storage as storage
import atr.storage.outcome as outcome
import atr.storage.types as types
import atr.template as template
import atr.util as util
import atr.web as web

type DELETE_OPENPGP_KEY = Literal["delete_openpgp_key"]
type DELETE_SSH_KEY = Literal["delete_ssh_key"]
type UPDATE_COMMITTEE_KEYS = Literal["update_committee_keys"]


class AddOpenPGPKeyForm(form.Form):
    public_key: str = form.label(
        "Public OpenPGP key",
        'Your public key should be in ASCII-armored format, starting with "-----BEGIN PGP PUBLIC KEY BLOCK-----"',
        widget=form.Widget.TEXTAREA,
    )
    selected_committees: form.StrList = form.label(
        "Associate key with committees",
        "Select the committees with which to associate your key.",
    )

    @pydantic.model_validator(mode="after")
    def validate_at_least_one_committee(self) -> "AddOpenPGPKeyForm":
        if not self.selected_committees:
            raise ValueError("You must select at least one committee to associate with this key")
        return self


class AddSSHKeyForm(form.Form):
    key: str = form.label(
        "SSH public key",
        "Your SSH public key should be in the standard format, starting with a key type"
        ' (like "ssh-rsa" or "ssh-ed25519") followed by the key data.',
        widget=form.Widget.TEXTAREA,
    )


class DeleteOpenPGPKeyForm(form.Form):
    variant: DELETE_OPENPGP_KEY = form.value(DELETE_OPENPGP_KEY)
    fingerprint: str = form.label("Fingerprint", widget=form.Widget.HIDDEN)


class DeleteSSHKeyForm(form.Form):
    variant: DELETE_SSH_KEY = form.value(DELETE_SSH_KEY)
    fingerprint: str = form.label("Fingerprint", widget=form.Widget.HIDDEN)


class UpdateCommitteeKeysForm(form.Empty):
    variant: UPDATE_COMMITTEE_KEYS = form.value(UPDATE_COMMITTEE_KEYS)
    committee_name: str = form.label("Committee name", widget=form.Widget.HIDDEN)


type KeysForm = Annotated[
    DeleteOpenPGPKeyForm | DeleteSSHKeyForm | UpdateCommitteeKeysForm,
    form.DISCRIMINATOR,
]


class UpdateKeyCommitteesForm(form.Form):
    selected_committees: form.StrList = form.label(
        "Associated PMCs",
        widget=form.Widget.CUSTOM,
    )


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
            description="Select the committee with which to associate these keys.",
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
