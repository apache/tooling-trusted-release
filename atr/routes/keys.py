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
import base64
import binascii
import datetime
import hashlib
import logging
import logging.handlers
import pathlib
import textwrap
from collections.abc import Awaitable, Callable, Sequence

import aiofiles.os
import aiohttp
import asfquart as asfquart
import asfquart.base as base
import quart
import werkzeug.datastructures as datastructures
import werkzeug.exceptions as exceptions
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.models.sql as sql
import atr.revision as revision
import atr.routes as routes
import atr.routes.compose as compose
import atr.storage as storage
import atr.storage.types as types
import atr.template as template
import atr.user as user
import atr.util as util


class AddSSHKeyForm(util.QuartFormTyped):
    key = wtforms.StringField(
        "SSH public key",
        widget=wtforms.widgets.TextArea(),
        render_kw={"placeholder": "Paste your SSH public key here (in the format used in authorized_keys files)"},
        description=(
            "Your SSH public key should be in the standard format, starting with a key type"
            ' (like "ssh-rsa" or "ssh-ed25519") followed by the key data.'
        ),
    )
    submit = wtforms.SubmitField("Add SSH key")


class DeleteKeyForm(util.QuartFormTyped):
    submit = wtforms.SubmitField("Delete key")


class SshFingerprintError(ValueError):
    pass


class UpdateCommitteeKeysForm(util.QuartFormTyped):
    submit = wtforms.SubmitField("Regenerate KEYS file")


class UploadKeyFormBase(util.QuartFormTyped):
    key = wtforms.FileField(
        "KEYS file",
        validators=[wtforms.validators.Optional()],
        description=(
            "Upload a KEYS file containing multiple PGP public keys."
            " The file should contain keys in ASCII-armored format, starting with"
            ' "-----BEGIN PGP PUBLIC KEY BLOCK-----".'
        ),
    )
    keys_url = wtforms.URLField(
        "KEYS file URL",
        validators=[wtforms.validators.Optional(), wtforms.validators.URL()],
        render_kw={"placeholder": "Enter URL to KEYS file"},
        description="Enter a URL to a KEYS file. This will be fetched by the server.",
    )
    submit = wtforms.SubmitField("Upload KEYS file")
    selected_committee = wtforms.SelectField(
        "Associate keys with committees",
        choices=[(c.name, c.display_name) for c in [] if (not util.committee_is_standing(c.name))],
        coerce=str,
        option_widget=wtforms.widgets.RadioInput(),
        widget=wtforms.widgets.ListWidget(prefix_label=False),
        validators=[wtforms.validators.InputRequired("You must select at least one committee")],
        description=(
            "Select the committee with which to associate these keys. You must be a member of the selected committee."
        ),
    )

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


@routes.committer("/keys/add", methods=["GET", "POST"])
async def add(session: routes.CommitterSession) -> str:
    """Add a new public signing key to the user's account."""
    key_info = None

    # Get committees for all projects the user is a member of
    async with db.session() as data:
        project_list = session.committees + session.projects
        user_committees = await data.committee(name_in=project_list).all()

    committee_choices = [(c.name, c.display_name or c.name) for c in user_committees]

    class AddOpenPGPKeyForm(util.QuartFormTyped):
        public_key = wtforms.TextAreaField(
            "Public OpenPGP key",
            validators=[wtforms.validators.InputRequired("Public key is required")],
            render_kw={"placeholder": "Paste your ASCII-armored public OpenPGP key here..."},
            description="Your public key should be in ASCII-armored format, starting with"
            ' "-----BEGIN PGP PUBLIC KEY BLOCK-----"',
        )
        selected_committees = wtforms.SelectMultipleField(
            "Associate key with committees",
            validators=[wtforms.validators.InputRequired("You must select at least one committee")],
            coerce=str,
            choices=committee_choices,
            option_widget=wtforms.widgets.CheckboxInput(),
            widget=wtforms.widgets.ListWidget(prefix_label=False),
            description="Select the committees with which to associate your key.",
        )
        submit = wtforms.SubmitField("Add OpenPGP key")

    form = await AddOpenPGPKeyForm.create_form(
        data=await quart.request.form if quart.request.method == "POST" else None
    )

    if await form.validate_on_submit():
        try:
            asf_uid = session.uid
            key_text: str = util.unwrap(form.public_key.data)
            selected_committee_names: list[str] = util.unwrap(form.selected_committees.data)

            async with storage.write(asf_uid) as write:
                wafm = write.as_foundation_member().result_or_raise()
                ocr: types.Outcome[types.Key] = await wafm.keys.ensure_stored_one(key_text)
                key = ocr.result_or_raise()

                for selected_committee_name in selected_committee_names:
                    wacm = write.as_committee_member(selected_committee_name).result_or_raise()
                    outcome: types.Outcome[types.LinkedCommittee] = await wacm.keys.associate_fingerprint(
                        key.key_model.fingerprint
                    )
                    outcome.result_or_raise()

                await quart.flash(f"OpenPGP key {key.key_model.fingerprint.upper()} added successfully.", "success")
            # Clear form data on success by creating a new empty form instance
            form = await AddOpenPGPKeyForm.create_form()

        except routes.FlashError as e:
            logging.warning("FlashError adding OpenPGP key: %s", e)
            await quart.flash(str(e), "error")
        except Exception as e:
            logging.exception("Error adding OpenPGP key:")
            await quart.flash(f"An unexpected error occurred: {e!s}", "error")

    return await template.render(
        "keys-add.html",
        asf_id=session.uid,
        user_committees=user_committees,
        form=form,
        key_info=key_info,
        algorithms=routes.algorithms,
    )


@routes.committer("/keys/delete", methods=["POST"])
async def delete(session: routes.CommitterSession) -> response.Response:
    """Delete a public signing key or SSH key from the user's account."""
    form = await DeleteKeyForm.create_form(data=await quart.request.form)

    if not await form.validate_on_submit():
        return await session.redirect(keys, error="Invalid request for key deletion.")

    fingerprint = (await quart.request.form).get("fingerprint")
    if not fingerprint:
        return await session.redirect(keys, error="Missing key fingerprint for deletion.")

    # Try to delete an SSH key first
    async with db.session() as data:
        ssh_key = await data.ssh_key(fingerprint=fingerprint, asf_uid=session.uid).get()
        if ssh_key:
            # Delete the SSH key
            await data.delete(ssh_key)
            await data.commit()
            return await session.redirect(keys, success="SSH key deleted successfully")

    # Otherwise, delete an OpenPGP key
    async with storage.write(session.uid) as write:
        wafm = write.as_foundation_member().result_or_none()
        if wafm is None:
            return await session.redirect(keys, error="Key not found or not owned by you")
        outcome: types.Outcome[sql.PublicSigningKey] = await wafm.keys.delete_key(fingerprint)
        match outcome:
            case types.OutcomeResult():
                return await session.redirect(keys, success="Key deleted successfully")
            case types.OutcomeException():
                return await session.redirect(keys, error=f"Error deleting key: {outcome.exception_or_raise()}")

    return await session.redirect(keys, error="Key not found or not owned by you")


@routes.committer("/keys/details/<fingerprint>", methods=["GET", "POST"])
async def details(session: routes.CommitterSession, fingerprint: str) -> str | response.Response:
    """Display details for a specific OpenPGP key."""
    fingerprint = fingerprint.lower()
    async with db.session() as data:
        key, is_owner = await _key_and_is_owner(data, session, fingerprint)
        form = None
        if is_owner:
            project_list = session.committees + session.projects
            user_committees = await data.committee(name_in=project_list).all()
            committee_choices = [(c.name, c.display_name or c.name) for c in user_committees]

            class UpdateKeyCommitteesForm(util.QuartFormTyped):
                selected_committees = wtforms.SelectMultipleField(
                    "Associated PMCs",
                    coerce=str,
                    choices=committee_choices,
                    option_widget=wtforms.widgets.CheckboxInput(),
                    widget=wtforms.widgets.ListWidget(prefix_label=False),
                    description="Select the committees associated with this key.",
                )
                submit = wtforms.SubmitField("Update associations")

            form = await UpdateKeyCommitteesForm.create_form(
                data=await quart.request.form if (quart.request.method == "POST") else None
            )

            if quart.request.method == "GET":
                form.selected_committees.data = [c.name for c in key.committees]

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
                async with storage.write(session.uid) as write:
                    for affected_committee_name in affected_committee_names:
                        wacm = write.as_committee_member(affected_committee_name).result_or_none()
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
        algorithms=routes.algorithms,
        now=datetime.datetime.now(datetime.UTC),
        asf_id=session.uid,
    )


@routes.committer("/keys/export/<committee_name>")
async def export(session: routes.CommitterSession, committee_name: str) -> quart.Response:
    """Export a KEYS file for a specific committee."""
    if committee_name not in (session.committees + session.projects):
        quart.abort(403, description=f"You are not authorised to update the KEYS file for {committee_name}")

    async with db.session() as data:
        full_keys_file_content = await _keys_formatter(committee_name, data)

    return quart.Response(full_keys_file_content, mimetype="text/plain")


@routes.committer("/keys/import/<project_name>/<version_name>", methods=["POST"])
async def import_selected_revision(
    session: routes.CommitterSession, project_name: str, version_name: str
) -> response.Response:
    await session.check_access(project_name)

    await util.validate_empty_form()
    release = await session.release(project_name, version_name, with_committee=True)
    keys_path = util.release_directory(release) / "KEYS"
    async with aiofiles.open(keys_path, encoding="utf-8") as f:
        keys_text = await f.read()
    if release.committee is None:
        raise routes.FlashError("No committee found for release")

    async with storage.write(session.uid) as write:
        wacm = write.as_committee_member(release.committee.name).result_or_raise()
        outcomes: types.Outcomes[types.Key] = await wacm.keys.ensure_associated(keys_text)
        success_count = outcomes.result_count
        error_count = outcomes.exception_count

    message = f"Uploaded {success_count} keys,"
    if error_count > 0:
        message += f" failed to upload {error_count} keys for {release.committee.name}"
    # Remove the KEYS file if 100% imported
    if (success_count > 0) and (error_count == 0):
        description = "Removed KEYS file after successful import through web interface"
        async with revision.create_and_manage(
            project_name, version_name, session.uid, description=description
        ) as creating:
            path_in_new_revision = creating.interim_path / "KEYS"
            await aiofiles.os.remove(path_in_new_revision)
    return await session.redirect(
        compose.selected,
        success=message,
        project_name=project_name,
        version_name=version_name,
    )


def key_ssh_fingerprint(ssh_key_string: str) -> str:
    # The format should be as in *.pub or authorized_keys files
    # I.e. TYPE DATA COMMENT
    ssh_key_parts = ssh_key_string.strip().split()
    if len(ssh_key_parts) >= 2:
        # We discard the type, which is ssh_key_parts[0]
        key_data = ssh_key_parts[1]
        # We discard the comment, which is ssh_key_parts[2]

        # Standard fingerprint calculation
        try:
            decoded_key_data = base64.b64decode(key_data)
        except binascii.Error as e:
            raise ValueError(f"Invalid base64 encoding in key data: {e}") from e

        digest = hashlib.sha256(decoded_key_data).digest()
        fingerprint_b64 = base64.b64encode(digest).decode("utf-8").rstrip("=")

        # Prefix follows the standard format
        return f"SHA256:{fingerprint_b64}"

    raise ValueError("Invalid SSH key format")


@routes.committer("/keys")
async def keys(session: routes.CommitterSession) -> str:
    """View all keys associated with the user's account."""
    committees_to_query = list(set(session.committees + session.projects))

    delete_form = await DeleteKeyForm.create_form()
    update_committee_keys_form = await UpdateCommitteeKeysForm.create_form()

    async with db.session() as data:
        user_keys = await data.public_signing_key(apache_uid=session.uid.lower(), _committees=True).all()
        user_ssh_keys = await data.ssh_key(asf_uid=session.uid).all()
        user_committees_with_keys = await data.committee(name_in=committees_to_query, _public_signing_keys=True).all()
    for key in user_keys:
        key.committees.sort(key=lambda c: c.name)

    status_message = quart.request.args.get("status_message")
    status_type = quart.request.args.get("status_type")

    return await template.render(
        "keys-review.html",
        asf_id=session.uid,
        user_keys=user_keys,
        user_ssh_keys=user_ssh_keys,
        committees=user_committees_with_keys,
        algorithms=routes.algorithms,
        status_message=status_message,
        status_type=status_type,
        now=datetime.datetime.now(datetime.UTC),
        delete_form=delete_form,
        update_committee_keys_form=update_committee_keys_form,
        email_from_key=util.email_from_uid,
        committee_is_standing=util.committee_is_standing,
    )


@routes.committer("/keys/ssh/add", methods=["GET", "POST"])
async def ssh_add(session: routes.CommitterSession) -> response.Response | str:
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
            fingerprint = await ssh_key_add(key, session.uid)
        except SshFingerprintError as e:
            if isinstance(form.key.errors, list):
                form.key.errors.append(str(e))
            else:
                form.key.errors = [str(e)]
        else:
            success_message = f"SSH key added successfully: {fingerprint}"
            return await session.redirect(keys, success=success_message)

    return await template.render(
        "keys-ssh-add.html",
        asf_id=session.uid,
        form=form,
        fingerprint=fingerprint,
    )


async def ssh_key_add(key: str, asf_uid: str) -> str:
    try:
        fingerprint = await asyncio.to_thread(key_ssh_fingerprint, key)
    except Exception as e:
        raise SshFingerprintError(str(e)) from e
    async with db.session() as data:
        data.add(sql.SSHKey(fingerprint=fingerprint, key=key, asf_uid=asf_uid))
        await data.commit()
    return fingerprint


async def ssh_key_delete(fingerprint: str, asf_uid: str) -> None:
    async with db.session() as data:
        ssh_key = await data.ssh_key(fingerprint=fingerprint, asf_uid=asf_uid).demand(exceptions.NotFound())
        await data.delete(ssh_key)
        await data.commit()


@routes.committer("/keys/update-committee-keys/<committee_name>", methods=["POST"])
async def update_committee_keys(session: routes.CommitterSession, committee_name: str) -> response.Response:
    """Generate and save the KEYS file for a specific committee."""
    form = await UpdateCommitteeKeysForm.create_form()
    if not await form.validate_on_submit():
        return await session.redirect(keys, error="Invalid request to update KEYS file.")

    async with storage.write(session.uid) as write:
        wacm = write.as_committee_member(committee_name).result_or_raise()
        match await wacm.keys.autogenerate_keys_file():
            case types.OutcomeResult():
                await quart.flash(
                    f'Successfully regenerated the KEYS file for the "{committee_name}" committee.', "success"
                )
            case types.OutcomeException():
                await quart.flash(f"Error regenerating the KEYS file for the {committee_name} committee.", "error")

    return await session.redirect(keys)


@routes.committer("/keys/upload", methods=["GET", "POST"])
async def upload(session: routes.CommitterSession) -> str:
    """Upload a KEYS file containing multiple OpenPGP keys."""
    # Get committees for all projects the user is a member of
    async with db.session() as data:
        project_list = session.committees + session.projects
        user_committees = await data.committee(name_in=project_list).all()

    class UploadKeyForm(UploadKeyFormBase):
        selected_committee = wtforms.SelectField(
            "Associate keys with committee",
            choices=[(c.name, c.display_name) for c in user_committees if (not util.committee_is_standing(c.name))],
            coerce=str,
            option_widget=wtforms.widgets.RadioInput(),
            widget=wtforms.widgets.ListWidget(prefix_label=False),
            validators=[wtforms.validators.InputRequired("You must select at least one committee")],
            description=(
                "Select the committee with which to associate these keys."
                " You must be a member of the selected committee."
            ),
        )

    form = await UploadKeyForm.create_form()
    results: types.Outcomes[types.Key] | None = None

    async def render(
        error: str | None = None,
        submitted_committees: list[str] | None = None,
        all_user_committees: Sequence[sql.Committee] | None = None,
    ) -> str:
        # For easier happy pathing
        if error is not None:
            await quart.flash(error, "error")

        # Determine which committee list to use
        current_committees = all_user_committees if (all_user_committees is not None) else user_committees
        committee_map = {c.name: c.display_name for c in current_committees}

        return await template.render(
            "keys-upload.html",
            asf_id=session.uid,
            user_committees=current_committees,
            committee_map=committee_map,
            form=form,
            results=results,
            algorithms=routes.algorithms,
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

        outcomes = await _upload_keys(session.uid, keys_text, selected_committee)
        results = outcomes
        success_count = outcomes.result_count
        error_count = outcomes.exception_count
        total_count = success_count + error_count

        await quart.flash(
            f"Processed {total_count} keys: {success_count} successful, {error_count} failed",
            "success" if success_count > 0 else "error",
        )
        return await render(
            submitted_committees=[selected_committee],
            all_user_committees=user_committees,
        )

    return await render()


async def _format_keys_file(
    committee_name_for_header: str,
    key_count_for_header: int,
    key_blocks_str: str,
) -> str:
    timestamp_str = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")
    purpose_text = (
        f"This file contains the {key_count_for_header} OpenPGP public keys used by "
        f"committers of the Apache {committee_name_for_header} projects to sign official "
        f"release artifacts. Verifying the signature on a downloaded artifact using one "
        f"of the keys in this file provides confidence that the artifact is authentic "
        f"and was published by the committee."
    )
    wrapped_purpose = "\n".join(
        textwrap.wrap(
            purpose_text,
            width=62,
            initial_indent="# ",
            subsequent_indent="# ",
            break_long_words=False,
            replace_whitespace=False,
        )
    )

    header_content = (
        f"""\
# Apache Software Foundation (ASF)
# Signing keys for the {committee_name_for_header} committee
# Generated on {timestamp_str} UTC
#
{wrapped_purpose}
#
# 1. Import these keys into your GPG keyring:
#    gpg --import KEYS
#
# 2. Verify the signature file against the release artifact:
#    gpg --verify "${{ARTIFACT}}.asc" "${{ARTIFACT}}"
#
# For details on Apache release signing and verification, see:
# https://infra.apache.org/release-signing.html
"""
        + "\n\n"
    )

    full_keys_file_content = header_content + key_blocks_str
    return full_keys_file_content


async def _get_keys_text(keys_url: str, render: Callable[[str], Awaitable[str]]) -> str:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(keys_url, allow_redirects=True) as response:
                response.raise_for_status()
                return await response.text()
    except aiohttp.ClientResponseError as e:
        raise base.ASFQuartException(f"Error fetching URL: {e.status} {e.message}")
    except aiohttp.ClientError as e:
        raise base.ASFQuartException(f"Error fetching URL: {e}")


async def _key_and_is_owner(
    data: db.Session, session: routes.CommitterSession, fingerprint: str
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


async def _keys_formatter(committee_name: str, data: db.Session) -> str:
    committee = await data.committee(name=committee_name, _public_signing_keys=True, _projects=True).demand(
        base.ASFQuartException(f"Committee {committee_name} not found", errorcode=404)
    )

    if not committee.public_signing_keys:
        raise base.ASFQuartException(
            f"No keys found for committee {committee_name} to generate KEYS file.", errorcode=404
        )

    if (not committee.projects) and (committee.name != "incubator"):
        raise base.ASFQuartException(f"No projects found associated with committee {committee_name}.", errorcode=404)

    sorted_keys = sorted(committee.public_signing_keys, key=lambda k: k.fingerprint)

    keys_content_list = []
    for key in sorted_keys:
        apache_uid = key.apache_uid.lower() if key.apache_uid else None
        # TODO: What if there is no email?
        email = util.email_from_uid(key.primary_declared_uid or "") or ""
        comments = []
        comments.append(f"Comment: {key.fingerprint.upper()}")
        if (apache_uid is None) or (email == f"{apache_uid}@apache.org"):
            comments.append(f"Comment: {email}")
        else:
            comments.append(f"Comment: {email} ({apache_uid})")
        comment_lines = "\n".join(comments)
        armored_key = key.ascii_armored_key
        # Use the Sequoia format
        # -----BEGIN PGP PUBLIC KEY BLOCK-----
        # Comment: C46D 6658 489D DE09 CE93  8AF8 7B6A 6401 BF99 B4A3
        # Comment: Redacted Name (CODE SIGNING KEY) <redacted@apache.org>
        #
        # [...]
        if isinstance(armored_key, bytes):
            # TODO: This should not happen, but it does
            armored_key = armored_key.decode("utf-8", errors="replace")
        armored_key = armored_key.replace("BLOCK-----", "BLOCK-----\n" + comment_lines, 1)
        keys_content_list.append(armored_key)

    key_blocks_str = "\n\n\n".join(keys_content_list) + "\n"

    committee_name_for_header = committee.display_name or committee.name
    key_count_for_header = len(committee.public_signing_keys)

    return await _format_keys_file(
        committee_name_for_header=committee_name_for_header,
        key_count_for_header=key_count_for_header,
        key_blocks_str=key_blocks_str,
    )


async def _upload_keys(
    asf_uid: str,
    filetext: str,
    selected_committee: str,
) -> types.Outcomes[types.Key]:
    async with storage.write(asf_uid) as write:
        wacm = write.as_committee_member(selected_committee).result_or_raise()
        outcomes: types.Outcomes[types.Key] = await wacm.keys.ensure_associated(filetext)
    return outcomes


async def _write_keys_file(
    committee_keys_dir: pathlib.Path,
    full_keys_file_content: str,
    committee_keys_path: pathlib.Path,
    committee_name: str,
) -> str | None:
    try:
        await asyncio.to_thread(committee_keys_dir.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread(util.chmod_directories, committee_keys_dir, permissions=0o755)
        await asyncio.to_thread(committee_keys_path.write_text, full_keys_file_content, encoding="utf-8")
    except OSError as e:
        error_msg = f"Failed to write KEYS file for committee {committee_name}: {e}"
        logging.exception(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"An unexpected error occurred writing KEYS for committee {committee_name}: {e}"
        logging.exception(error_msg)
        return error_msg
    return None
