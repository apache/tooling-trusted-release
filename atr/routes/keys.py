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
import re
import textwrap
from collections.abc import Sequence

import aiofiles.os
import asfquart as asfquart
import asfquart.base as base
import quart
import sqlmodel
import werkzeug.datastructures as datastructures
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.interaction as interaction
import atr.db.models as models
import atr.revision as revision
import atr.routes as routes
import atr.routes.compose as compose
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


class UpdateCommitteeKeysForm(util.QuartFormTyped):
    submit = wtforms.SubmitField("Update KEYS file")


@routes.committer("/keys/add", methods=["GET", "POST"])
async def add(session: routes.CommitterSession) -> str:
    """Add a new public signing key to the user's account."""
    key_info = None

    # Get committees for all projects the user is a member of
    async with db.session() as data:
        project_list = session.committees + session.projects
        user_committees = await data.committee(name_in=project_list).all()

    committee_choices = [(c.name, c.display_name or c.name) for c in user_committees]

    class AddGpgKeyForm(util.QuartFormTyped):
        public_key = wtforms.TextAreaField(
            "Public GPG key",
            validators=[wtforms.validators.InputRequired("Public key is required")],
            render_kw={"placeholder": "Paste your ASCII-armored public GPG key here..."},
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
        submit = wtforms.SubmitField("Add GPG key")

    form = await AddGpgKeyForm.create_form(data=await quart.request.form if quart.request.method == "POST" else None)

    if await form.validate_on_submit():
        try:
            public_key_data: str = util.unwrap(form.public_key.data)
            selected_committees_data: list[str] = util.unwrap(form.selected_committees.data)

            invalid_committees = [
                committee
                for committee in selected_committees_data
                if (committee not in session.committees) and (committee not in session.projects)
            ]
            if invalid_committees:
                raise routes.FlashError(f"Invalid PMC selection: {', '.join(invalid_committees)}")

            key_info = await interaction.key_user_add(session.uid, public_key_data, selected_committees_data)
            if key_info:
                await quart.flash(f"GPG key {key_info.get('fingerprint', '')} added successfully.", "success")
            # Clear form data on success by creating a new empty form instance
            form = await AddGpgKeyForm.create_form()

        except routes.FlashError as e:
            logging.warning("FlashError adding GPG key: %s", e)
            await quart.flash(str(e), "error")
        except Exception as e:
            logging.exception("Exception adding GPG key:")
            await quart.flash(f"An unexpected error occurred: {e!s}", "error")

    return await quart.render_template(
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

    async with db.session() as data:
        async with data.begin():
            # Try to get a GPG key first
            key = await data.public_signing_key(fingerprint=fingerprint, apache_uid=session.uid).get()
            if key:
                # Delete the GPG key
                await data.delete(key)
                return await session.redirect(keys, success="GPG key deleted successfully")

            # If not a GPG key, try to get an SSH key
            ssh_key = await data.ssh_key(fingerprint=fingerprint, asf_uid=session.uid).get()
            if ssh_key:
                # Delete the SSH key
                await data.delete(ssh_key)
                return await session.redirect(keys, success="SSH key deleted successfully")

            # No key was found
            return await session.redirect(keys, error="Key not found or not owned by you")


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
    selected_committees = [release.committee.name]
    _upload_results, success_count, error_count, submitted_committees = await _upload_keys(
        session, keys_text, selected_committees
    )
    message = f"Uploaded {success_count} keys,"
    if error_count > 0:
        message += f" failed to upload {error_count} keys for {', '.join(submitted_committees)}"
    # Remove the KEYS file if 100% imported
    if (success_count > 0) and (error_count == 0):
        description = "Removed KEYS file after successful import through web interface"
        async with revision.create_and_manage(project_name, version_name, session.uid, description=description) as (
            new_revision_dir,
            _new_revision_number,
        ):
            path_in_new_revision = new_revision_dir / "KEYS"
            await aiofiles.os.remove(path_in_new_revision)
    return await session.redirect(
        compose.selected,
        success=message,
        project_name=project_name,
        version_name=version_name,
    )


async def key_add_post(
    session: routes.CommitterSession, request: quart.Request, user_committees: Sequence[models.Committee]
) -> dict | None:
    form = await routes.get_form(request)
    public_key = form.get("public_key")
    if not public_key:
        raise routes.FlashError("Public key is required")

    # Get selected PMCs from form
    selected_committees = form.getlist("selected_committees")
    if not selected_committees:
        raise routes.FlashError("You must select at least one PMC")

    # Ensure that the selected PMCs are ones of which the user is actually a member
    invalid_committees = [
        committee
        for committee in selected_committees
        if (committee not in session.committees) and (committee not in session.projects)
    ]
    if invalid_committees:
        raise routes.FlashError(f"Invalid PMC selection: {', '.join(invalid_committees)}")

    return await interaction.key_user_add(session.uid, public_key, selected_committees)


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
        user_keys = await data.public_signing_key(apache_uid=session.uid, _committees=True).all()
        user_ssh_keys = await data.ssh_key(asf_uid=session.uid).all()
        user_committees_with_keys = await data.committee(name_in=committees_to_query, _public_signing_keys=True).all()

    status_message = quart.request.args.get("status_message")
    status_type = quart.request.args.get("status_type")

    return await quart.render_template(
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
    )


@routes.committer("/keys/show-gpg/<fingerprint>", methods=["GET"])
async def show_gpg_key(session: routes.CommitterSession, fingerprint: str) -> str:
    """Display details for a specific GPG key."""
    async with db.session() as data:
        key = await data.public_signing_key(fingerprint=fingerprint).get()

    if not key:
        quart.abort(404, description="GPG key not found")

    authorised = False
    if key.apache_uid == session.uid:
        authorised = True
    else:
        user_affiliations = set(session.committees + session.projects)
        async with db.session() as data:
            key_committees = await data.execute(
                sqlmodel.select(models.KeyLink.committee_name).where(models.KeyLink.key_fingerprint == fingerprint)
            )
            key_committee_names = {row[0] for row in key_committees.all()}
        if user_affiliations.intersection(key_committee_names):
            authorised = True

    if not authorised:
        quart.abort(403, description="You are not authorised to view this key")

    return await quart.render_template(
        "keys-show-gpg.html",
        key=key,
        algorithms=routes.algorithms,
        now=datetime.datetime.now(datetime.UTC),
        asf_id=session.uid,
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
            fingerprint = await asyncio.to_thread(key_ssh_fingerprint, key)
        except ValueError as e:
            if isinstance(form.key.errors, list):
                form.key.errors.append(str(e))
            else:
                form.key.errors = [str(e)]
        else:
            async with db.session() as data:
                async with data.begin():
                    data.add(models.SSHKey(fingerprint=fingerprint, key=key, asf_uid=session.uid))
            return await session.redirect(keys, success=f"SSH key added successfully: {fingerprint}")

    return await quart.render_template(
        "keys-ssh-add.html",
        asf_id=session.uid,
        form=form,
        fingerprint=fingerprint,
    )


@routes.committer("/keys/update-committee-keys/<committee_name>", methods=["POST"])
async def update_committee_keys(session: routes.CommitterSession, committee_name: str) -> response.Response:
    """Generate and save the KEYS file for a specific committee."""
    form = await UpdateCommitteeKeysForm.create_form()
    if not await form.validate_on_submit():
        return await session.redirect(keys, error="Invalid request to update KEYS file.")

    if committee_name not in (session.committees + session.projects):
        quart.abort(403, description=f"You are not authorised to update the KEYS file for {committee_name}")

    async with db.session() as data:
        committee = await data.committee(name=committee_name, _public_signing_keys=True, _projects=True).demand(
            base.ASFQuartException(f"Committee {committee_name} not found", errorcode=404)
        )

        if not committee.public_signing_keys:
            return await session.redirect(
                keys, error=f"No keys found for committee {committee_name} to generate KEYS file."
            )

        if not committee.projects:
            return await session.redirect(keys, error=f"No projects found associated with committee {committee_name}.")

        sorted_keys = sorted(committee.public_signing_keys, key=lambda k: k.fingerprint)

        keys_content_list = []
        for key in sorted_keys:
            fingerprint_short = key.fingerprint[:16].upper()
            apache_uid = key.apache_uid
            declared_uid_str = key.declared_uid or ""
            email_match = re.search(r"<([^>]+)>", declared_uid_str)
            email = email_match.group(1) if email_match else declared_uid_str
            if email == f"{apache_uid}@apache.org":
                comment_line = f"# {fingerprint_short} {email}"
            else:
                comment_line = f"# {fingerprint_short} {email} ({apache_uid})"
            keys_content_list.append(f"{comment_line}\n\n{key.ascii_armored_key}")

        key_blocks_str = "\n\n\n".join(keys_content_list) + "\n"

        project_names_updated: list[str] = []
        write_errors: list[str] = []
        base_finished_dir = util.get_finished_dir()
        committee_name_for_header = committee.display_name or committee.name
        key_count_for_header = len(committee.public_signing_keys)

        for project in committee.projects:
            await _write_keys_file(
                project,
                base_finished_dir,
                committee_name_for_header,
                key_count_for_header,
                key_blocks_str,
                project_names_updated,
                write_errors,
            )
    if write_errors:
        error_summary = "; ".join(write_errors)
        await quart.flash(
            f"Completed KEYS update for {committee_name}, but encountered errors: {error_summary}", "error"
        )
    elif project_names_updated:
        projects_str = ", ".join(project_names_updated)
        await quart.flash(f"KEYS files updated successfully for projects: {projects_str}", "success")
    else:
        await quart.flash(f"No KEYS files were updated for committee {committee_name}.", "warning")

    return await session.redirect(keys)


@routes.committer("/keys/upload", methods=["GET", "POST"])
async def upload(session: routes.CommitterSession) -> str:
    """Upload a KEYS file containing multiple GPG keys."""
    # Get committees for all projects the user is a member of
    async with db.session() as data:
        project_list = session.committees + session.projects
        user_committees = await data.committee(name_in=project_list).all()

    class UploadKeyForm(util.QuartFormTyped):
        key = wtforms.FileField(
            "KEYS file",
            description=(
                "Upload a KEYS file containing multiple PGP public keys."
                " The file should contain keys in ASCII-armored format, starting with"
                ' "-----BEGIN PGP PUBLIC KEY BLOCK-----".'
            ),
        )
        submit = wtforms.SubmitField("Upload KEYS file")
        selected_committees = wtforms.SelectMultipleField(
            "Associate keys with committees",
            choices=[(c.name, c.display_name) for c in user_committees],
            coerce=str,
            option_widget=wtforms.widgets.CheckboxInput(),
            widget=wtforms.widgets.ListWidget(prefix_label=False),
            validators=[wtforms.validators.InputRequired("You must select at least one committee")],
            description=(
                "Select the committees with which to associate these keys."
                " You must be a member of the selected committees."
            ),
        )

    form = await UploadKeyForm.create_form()
    results: list[dict] = []
    submitted_committees: list[str] | None = None

    async def render(
        error: str | None = None,
        submitted_committees_list: list[str] | None = None,
        all_user_committees: Sequence[models.Committee] | None = None,
    ) -> str:
        # For easier happy pathing
        if error is not None:
            await quart.flash(error, "error")

        # Determine which committee list to use
        current_committees = all_user_committees if (all_user_committees is not None) else user_committees
        committee_map = {c.name: c.display_name for c in current_committees}

        return await quart.render_template(
            "keys-upload.html",
            asf_id=session.uid,
            user_committees=current_committees,
            committee_map=committee_map,
            form=form,
            results=results,
            algorithms=routes.algorithms,
            submitted_committees=submitted_committees_list,
        )

    if await form.validate_on_submit():
        key_file = form.key.data
        if not isinstance(key_file, datastructures.FileStorage):
            return await render(error="Invalid file upload")

        # Get selected committee list from the form
        selected_committees = form.selected_committees.data
        if not selected_committees:
            return await render(error="You must select at least one committee")
        # This is a KEYS file of multiple GPG keys
        # We need to parse it and add each key to the user's account
        keys_content = await asyncio.to_thread(key_file.read)
        keys_text = keys_content.decode("utf-8", errors="replace")

        upload_results, success_count, error_count, submitted_committees = await _upload_keys(
            session, keys_text, selected_committees
        )
        # We use results in a closure
        # So we have to mutate it, not replace it
        results[:] = upload_results

        await quart.flash(
            f"Processed {len(results)} keys: {success_count} successful, {error_count} failed",
            "success" if success_count > 0 else "error",
        )
        return await render(
            submitted_committees_list=submitted_committees,
            all_user_committees=user_committees,
        )

    return await render()


async def _upload_keys(
    session: routes.CommitterSession, keys_text: str, selected_committees: list[str]
) -> tuple[list[dict], int, int, list[str]]:
    key_blocks = util.parse_key_blocks(keys_text)
    if not key_blocks:
        raise routes.FlashError("No valid GPG keys found in the uploaded file")

    # Ensure that the selected committees are ones of which the user is actually a member
    invalid_committees = [
        committee for committee in selected_committees if (committee not in (session.committees + session.projects))
    ]
    if invalid_committees:
        raise routes.FlashError(f"Invalid committee selection: {', '.join(invalid_committees)}")

    # TODO: Do we modify this? Store a copy just in case, for the template to use
    submitted_committees = selected_committees[:]

    # Process each key block
    results = await _upload_process_key_blocks(key_blocks, selected_committees)
    if not results:
        raise routes.FlashError("No keys were added")

    success_count = sum(1 for result in results if result["status"] == "success")
    error_count = len(results) - success_count

    return results, success_count, error_count, submitted_committees


async def _upload_process_key_blocks(key_blocks: list[str], selected_committees: list[str]) -> list[dict]:
    """Process GPG key blocks and add them to the user's account."""
    results: list[dict] = []

    # Process each key block
    for i, key_block in enumerate(key_blocks):
        try:
            key_info = await interaction.key_user_add(None, key_block, selected_committees)
            if key_info:
                key_info["status"] = key_info.get("status", "success")
                key_info["email"] = key_info.get("email", "Unknown")
                key_info["committee_statuses"] = key_info.get("committee_statuses", {})
                results.append(key_info)
            else:
                # Handle case where key_user_add might return None
                results.append(
                    {
                        "status": "error",
                        "message": "Failed to process key (key_user_add returned None)",
                        "key_id": f"Key #{i + 1}",
                        "fingerprint": "Unknown",
                        "user_id": "Unknown",
                        "email": "Unknown",
                        "committee_statuses": {},
                    }
                )
        except routes.FlashError as e:
            logging.warning(f"FlashError processing key #{i + 1}: {e}")
            results.append(
                {
                    "status": "error",
                    "message": f"Validation Error: {e}",
                    "key_id": f"Key #{i + 1}",
                    "fingerprint": "Invalid",
                    "user_id": "Unknown",
                    "email": "Unknown",
                    "committee_statuses": {},
                }
            )
        except Exception as e:
            logging.exception(f"Exception processing key #{i + 1}:")
            results.append(
                {
                    "status": "error",
                    "message": f"Internal Exception: {e}",
                    "key_id": f"Key #{i + 1}",
                    "fingerprint": "Error",
                    "user_id": "Unknown",
                    "email": "Unknown",
                    "committee_statuses": {},
                }
            )

    # Primary key is email, secondary key is fingerprint
    results_sorted = sorted(results, key=lambda x: (x.get("email", "").lower(), x.get("fingerprint", "")))

    return results_sorted


async def _write_keys_file(
    project: models.Project,
    base_finished_dir: pathlib.Path,
    committee_name_for_header: str,
    key_count_for_header: int,
    key_blocks_str: str,
    project_names_updated: list[str],
    write_errors: list[str],
) -> None:
    project_name = project.name
    project_keys_dir = base_finished_dir / project_name
    project_keys_path = project_keys_dir / "KEYS"

    timestamp_str = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")
    purpose_text = (
        f"This file contains the PGP/GPG public keys used by committers of the "
        f"Apache {project_name} project to sign official release artifacts. "
        f"Verifying the signature on a downloaded artifact using one of the "
        f"keys in this file provides confidence that the artifact is authentic "
        f"and was published by the project team."
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
# Apache Software Foundation (ASF) project signing keys
#
# Project:   {project.display_name or project.name}
# Committee: {committee_name_for_header}
# Generated: {timestamp_str} UTC
# Contains:  {key_count_for_header} PGP/GPG public {"key" if key_count_for_header == 1 else "keys"}
#
# Purpose:
{wrapped_purpose}
#
# Usage (with GnuPG):
# 1. Import these keys into your GPG keyring:
#    gpg --import KEYS
#
# 2. Verify the signature file against the release artifact:
#    gpg --verify <artifact-name>.asc <artifact-name>
#
# For details on Apache release signing and verification, see:
# https://infra.apache.org/release-signing.html
"""
        + "\n\n"
    )

    full_keys_file_content = header_content + key_blocks_str
    try:
        await asyncio.to_thread(project_keys_dir.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread(project_keys_path.write_text, full_keys_file_content, encoding="utf-8")
        project_names_updated.append(project_name)
    except OSError as e:
        error_msg = f"Failed to write KEYS file for project {project_name}: {e}"
        logging.exception(error_msg)
        write_errors.append(error_msg)
    except Exception as e:
        error_msg = f"An unexpected error occurred writing KEYS for project {project_name}: {e}"
        logging.exception(error_msg)
        write_errors.append(error_msg)
