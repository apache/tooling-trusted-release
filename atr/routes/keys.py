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
import contextlib
import datetime
import hashlib
import logging
import logging.handlers
import pprint
import re
import shutil
import tempfile
from collections.abc import AsyncGenerator, Sequence

import asfquart as asfquart
import asfquart.auth as auth
import asfquart.base as base
import asfquart.session as session
import cryptography.hazmat.primitives.serialization as serialization
import gnupg
import quart
import werkzeug.datastructures as datastructures
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.routes as routes
import atr.util as util


class AddSSHKeyForm(util.QuartFormTyped):
    key = wtforms.StringField("SSH key", widget=wtforms.widgets.TextArea())
    submit = wtforms.SubmitField("Add SSH key")


@contextlib.asynccontextmanager
async def ephemeral_gpg_home() -> AsyncGenerator[str]:
    """Create a temporary directory for an isolated GPG home, and clean it up on exit."""
    # TODO: This is only used in key_user_add
    # We could even inline it there
    temp_dir = await asyncio.to_thread(tempfile.mkdtemp, prefix="gpg-")
    try:
        yield temp_dir
    finally:
        await asyncio.to_thread(shutil.rmtree, temp_dir)


async def key_add_post(
    web_session: session.ClientSession, request: quart.Request, user_committees: Sequence[models.Committee]
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
        if (committee not in web_session.committees) and (committee not in web_session.projects)
    ]
    if invalid_committees:
        raise routes.FlashError(f"Invalid PMC selection: {', '.join(invalid_committees)}")

    return await key_user_add(util.unwrap(web_session.uid), public_key, selected_committees)


def key_ssh_fingerprint(ssh_key_string: str) -> str:
    # The format should be as in *.pub or authorized_keys files
    # I.e. TYPE DATA COMMENT
    ssh_key_parts = ssh_key_string.strip().split()
    if len(ssh_key_parts) >= 2:
        key_type = ssh_key_parts[0]
        key_data = ssh_key_parts[1]
        # We discard the comment, which is ssh_key_parts[2]

        # Parse the key
        key = serialization.load_ssh_public_key(f"{key_type} {key_data}".encode())

        # Get raw public key bytes
        public_bytes = key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Calculate SHA256 hash
        digest = hashlib.sha256(public_bytes).digest()
        fingerprint = base64.b64encode(digest).decode("utf-8").rstrip("=")

        # TODO: Do we really want to use a prefix?
        return f"SHA256:{fingerprint}"

    raise ValueError("Invalid SSH key format")


async def key_user_add(asf_uid: str | None, public_key: str, selected_committees: list[str]) -> dict | None:
    if not public_key:
        raise routes.FlashError("Public key is required")

    # Import the key into GPG to validate and extract info
    # TODO: We'll just assume for now that gnupg.GPG() doesn't need to be async
    async with ephemeral_gpg_home() as gpg_home:
        gpg = gnupg.GPG(gnupghome=gpg_home)
        import_result = await asyncio.to_thread(gpg.import_keys, public_key)

        if not import_result.fingerprints:
            raise routes.FlashError("Invalid public key format")

        fingerprint = import_result.fingerprints[0]
        if fingerprint is not None:
            fingerprint = fingerprint.lower()
        # APP.logger.info("Import result: %s", vars(import_result))
        # Get key details
        # We could probably use import_result instead
        # But this way it shows that they've really been imported
        keys = await asyncio.to_thread(gpg.list_keys)

    # Then we have the properties listed here:
    # https://gnupg.readthedocs.io/en/latest/#listing-keys
    # Note that "fingerprint" is not listed there, but we have it anyway...
    key = next((k for k in keys if (k["fingerprint"] is not None) and (k["fingerprint"].lower() == fingerprint)), None)
    if not key:
        raise routes.FlashError("Failed to import key")
    if (key.get("algo") == "1") and (int(key.get("length", "0")) < 2048):
        # https://infra.apache.org/release-signing.html#note
        # Says that keys must be at least 2048 bits
        raise routes.FlashError("Key is not long enough; must be at least 2048 bits")
    if asf_uid is None:
        for uid in key["uids"]:
            match = re.search(r"([A-Za-z0-9]+)@apache.org", uid)
            if match:
                asf_uid = match.group(1).lower()
                break
        else:
            logging.warning(f"key_user_add called with no ASF UID: {keys}")
    if asf_uid is None:
        # We place this here to make it easier on the type checkers
        raise routes.FlashError("No Apache UID found in the key UIDs")

    # Store key in database
    async with db.session() as data:
        return await key_user_session_add(asf_uid, public_key, key, selected_committees, data)


async def key_user_session_add(
    asf_uid: str,
    public_key: str,
    key: dict,
    selected_committees: list[str],
    data: db.Session,
) -> dict | None:
    # TODO: Check if key already exists
    # psk_statement = select(PublicSigningKey).where(PublicSigningKey.apache_uid == session.uid)

    # # If uncommented, this will prevent a user from adding a second key
    # existing_key = (await db_session.execute(statement)).scalar_one_or_none()
    # if existing_key:
    #     return ("You already have a key registered", None)

    fingerprint = key.get("fingerprint")
    if not isinstance(fingerprint, str):
        raise routes.FlashError("Invalid key fingerprint")
    fingerprint = fingerprint.lower()
    uids = key.get("uids")
    async with data.begin():
        if existing := await data.public_signing_key(fingerprint=fingerprint, apache_uid=asf_uid).get():
            raise routes.FlashError(f"Key already exists: {existing.fingerprint}")

        # Create new key record
        key_record = models.PublicSigningKey(
            fingerprint=fingerprint,
            algorithm=int(key["algo"]),
            length=int(key.get("length", "0")),
            created=datetime.datetime.fromtimestamp(int(key["date"])),
            expires=datetime.datetime.fromtimestamp(int(key["expires"])) if key.get("expires") else None,
            declared_uid=uids[0] if uids else None,
            apache_uid=asf_uid,
            ascii_armored_key=public_key,
        )
        data.add(key_record)

        # Link key to selected PMCs
        for committee_name in selected_committees:
            committee = await data.committee(name=committee_name).get()
            if committee and committee.id:
                link = models.KeyLink(committee_id=committee.id, key_fingerprint=key_record.fingerprint)
                data.add(link)
            else:
                # TODO: Log? Add to "error"?
                continue

    return {
        "key_id": key["keyid"],
        "fingerprint": key["fingerprint"].lower() if key.get("fingerprint") else "Unknown",
        "user_id": key["uids"][0] if key.get("uids") else "Unknown",
        "creation_date": datetime.datetime.fromtimestamp(int(key["date"])),
        "expiration_date": datetime.datetime.fromtimestamp(int(key["expires"])) if key.get("expires") else None,
        "data": pprint.pformat(key),
    }


@routes.app_route("/keys/add", methods=["GET", "POST"])
@auth.require(auth.Requirements.committer)
async def root_keys_add() -> str:
    """Add a new public signing key to the user's account."""
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    key_info = None

    # Get committees for all projects the user is a member of
    async with db.session() as data:
        project_list = web_session.committees + web_session.projects
        user_committees = await data.committee(name_in=project_list).all()

    if quart.request.method == "POST":
        try:
            key_info = await key_add_post(web_session, quart.request, user_committees)
        except routes.FlashError as e:
            logging.exception("FlashError:")
            await quart.flash(str(e), "error")
        except Exception as e:
            logging.exception("Exception:")
            await quart.flash(f"Exception: {e}", "error")

    return await quart.render_template(
        "keys-add.html",
        asf_id=web_session.uid,
        user_committees=user_committees,
        key_info=key_info,
        algorithms=routes.algorithms,
    )


@routes.app_route("/keys/delete", methods=["POST"])
@auth.require(auth.Requirements.committer)
async def root_keys_delete() -> response.Response:
    """Delete a public signing key from the user's account."""
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)
    uid = util.unwrap(web_session.uid)

    form = await routes.get_form(quart.request)
    fingerprint = form.get("fingerprint")
    if not fingerprint:
        await quart.flash("No key fingerprint provided", "error")
        return quart.redirect(quart.url_for("root_keys_review"))

    async with db.session() as data:
        async with data.begin():
            # Try to get a GPG key first
            key = await data.public_signing_key(fingerprint=fingerprint, apache_uid=uid).get()
            if key:
                # Delete the GPG key
                await data.delete(key)
                await quart.flash("GPG key deleted successfully", "success")
                return quart.redirect(quart.url_for("root_keys_review"))

            # If not a GPG key, try to get an SSH key
            ssh_key = await data.ssh_key(fingerprint=fingerprint, asf_uid=uid).get()
            if ssh_key:
                # Delete the SSH key
                await data.delete(ssh_key)
                await quart.flash("SSH key deleted successfully", "success")
                return quart.redirect(quart.url_for("root_keys_review"))

            # No key was found
            await quart.flash("Key not found or not owned by you", "error")
            return quart.redirect(quart.url_for("root_keys_review"))


@routes.app_route("/keys/review")
@auth.require(auth.Requirements.committer)
async def root_keys_review() -> str:
    """Show all keys associated with the user's account."""
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)
    uid = util.unwrap(web_session.uid)

    # Get all existing keys for the user
    async with db.session() as data:
        user_keys = await data.public_signing_key(apache_uid=uid, _committees=True).all()
        user_ssh_keys = await data.ssh_key(asf_uid=uid).all()

    status_message = quart.request.args.get("status_message")
    status_type = quart.request.args.get("status_type")

    return await quart.render_template(
        "keys-review.html",
        asf_id=web_session.uid,
        user_keys=user_keys,
        user_ssh_keys=user_ssh_keys,
        algorithms=routes.algorithms,
        status_message=status_message,
        status_type=status_type,
        now=datetime.datetime.now(datetime.UTC),
    )


@routes.app_route("/keys/ssh/add", methods=["GET", "POST"])
@auth.require(auth.Requirements.committer)
async def root_keys_ssh_add() -> response.Response | str:
    """Add a new SSH key to the user's account."""
    # TODO: Make an auth.require wrapper that gives the session automatically
    # And the form if it's a POST handler? Might be hard to type
    # But we can use variants of the function
    # GET, POST, GET_POST are all we need
    # We could even include auth in the function names
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)
    uid = util.unwrap(web_session.uid)

    form = await AddSSHKeyForm.create_form()
    fingerprint = None
    if await form.validate_on_submit():
        key: str = util.unwrap(form.key.data)
        fingerprint = await asyncio.to_thread(key_ssh_fingerprint, key)
        async with db.session() as data:
            async with data.begin():
                data.add(models.SSHKey(fingerprint=fingerprint, key=key, asf_uid=uid))
        await quart.flash(f"SSH key added successfully: {fingerprint}", "success")
        return quart.redirect(quart.url_for("root_keys_review"))

    return await quart.render_template(
        "keys-ssh-add.html",
        asf_id=web_session.uid,
        form=form,
        fingerprint=fingerprint,
    )


@routes.app_route("/keys/upload", methods=["GET", "POST"])
@auth.require(auth.Requirements.committer)
async def root_keys_upload() -> str:
    """Upload a KEYS file containing multiple GPG keys."""
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    # Get committees for all projects the user is a member of
    async with db.session() as data:
        project_list = web_session.committees + web_session.projects
        user_committees = await data.committee(name_in=project_list).all()

    class UploadKeyForm(util.QuartFormTyped):
        key = wtforms.FileField("KEYS file")
        submit = wtforms.SubmitField("Upload KEYS file")
        selected_committee = wtforms.SelectField("PMCs", choices=[(c.name, c.name) for c in user_committees])

    form = await UploadKeyForm.create_form()
    results: list[dict] = []

    async def render(error: str | None = None) -> str:
        # For easier happy pathing
        if error is not None:
            await quart.flash(error, "error")
        return await quart.render_template(
            "keys-upload.html",
            asf_id=web_session.uid,
            user_committees=user_committees,
            form=form,
            results=results,
            algorithms=routes.algorithms,
        )

    if await form.validate_on_submit():
        key_file = form.key.data
        if not isinstance(key_file, datastructures.FileStorage):
            return await render(error="Invalid file upload")

        # This is a KEYS file of multiple GPG keys
        # We need to parse it and add each key to the user's account
        key_blocks = await _upload_key_blocks(key_file)
        if not key_blocks:
            return await render(error="No valid GPG keys found in the uploaded file")

        # Get selected committee from the form
        selected_committee = form.selected_committee.data
        if not selected_committee:
            return await render(error="You must select at least one committee")

        # Ensure that the selected committee is one of which the user is actually a member
        if selected_committee not in (web_session.committees + web_session.projects):
            return await render(error=f"You are not a member of {selected_committee}")

        # Process each key block
        results = await _upload_process_key_blocks(key_blocks, selected_committee)
        if not results:
            return await render(error="No keys were added")

        success_count = sum(1 for r in results if r["status"] == "success")
        error_count = len(results) - success_count
        await quart.flash(
            f"Processed {len(results)} keys: {success_count} successful, {error_count} failed",
            "success" if success_count > 0 else "error",
        )
    return await render()


async def _upload_key_blocks(key_file: datastructures.FileStorage) -> list[str]:
    """Extract GPG key blocks from a KEYS file."""
    # Read the file content
    keys_content = await asyncio.to_thread(key_file.read)
    keys_text = keys_content.decode("utf-8", errors="replace")

    # Extract GPG key blocks
    key_blocks = []
    current_block = []
    in_key_block = False

    for line in keys_text.splitlines():
        if line.strip() == "-----BEGIN PGP PUBLIC KEY BLOCK-----":
            in_key_block = True
            current_block = [line]
        elif (line.strip() == "-----END PGP PUBLIC KEY BLOCK-----") and in_key_block:
            current_block.append(line)
            key_blocks.append("\n".join(current_block))
            in_key_block = False
        elif in_key_block:
            current_block.append(line)

    return key_blocks


async def _upload_process_key_blocks(key_blocks: list[str], selected_committee: str) -> list[dict]:
    """Process GPG key blocks and add them to the user's account."""
    results: list[dict] = []

    # Process each key block
    for i, key_block in enumerate(key_blocks):
        try:
            key_info = await key_user_add(None, key_block, [selected_committee])
            if key_info:
                key_info["status"] = "success"
                key_info["message"] = "Key added successfully"
                results.append(key_info)
        except Exception as e:
            logging.exception("Exception adding key:")
            results.append(
                {
                    "status": "error",
                    "message": f"Exception: {e}",
                    "key_id": f"Key #{i + 1}",
                    "fingerprint": "Error",
                    "user_id": "Unknown",
                }
            )

    return results
