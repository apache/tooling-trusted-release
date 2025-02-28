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
import logging
import logging.handlers
import pprint
import shutil
import tempfile
from collections.abc import AsyncGenerator, Sequence
from contextlib import asynccontextmanager
from typing import cast

import gnupg
from quart import Request, flash, redirect, render_template, request, url_for
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlmodel import select
from werkzeug.datastructures import MultiDict
from werkzeug.wrappers.response import Response

from asfquart import APP
from asfquart.auth import Requirements, require
from asfquart.base import ASFQuartException
from asfquart.session import ClientSession
from asfquart.session import read as session_read
from atr.db import get_session
from atr.db.models import (
    PMC,
    PMCKeyLink,
    PublicSigningKey,
)
from atr.routes import FlashError, algorithms, app_route


@asynccontextmanager
async def ephemeral_gpg_home() -> AsyncGenerator[str]:
    """Create a temporary directory for an isolated GPG home, and clean it up on exit."""
    # TODO: This is only used in key_user_add
    # We could even inline it there
    temp_dir = await asyncio.to_thread(tempfile.mkdtemp, prefix="gpg-")
    try:
        yield temp_dir
    finally:
        await asyncio.to_thread(shutil.rmtree, temp_dir)


async def get_form(request: Request) -> MultiDict:
    # The request.form() method in Quart calls a synchronous tempfile method
    # It calls quart.wrappers.request.form _load_form_data
    # Which calls quart.formparser parse and parse_func and parser.parse
    # Which calls _write which calls tempfile, which is synchronous
    # It's getting a tempfile back from some prior call
    # We can't just make blockbuster ignore the call because then it ignores it everywhere

    if APP is ...:
        raise RuntimeError("APP is not set")

    # Or quart.current_app?
    blockbuster = APP.config["blockbuster"]

    # Turn blockbuster off
    if blockbuster is not None:
        blockbuster.deactivate()
    form = await request.form
    # Turn blockbuster on
    if blockbuster is not None:
        blockbuster.activate()
    return form


async def key_add_post(session: ClientSession, request: Request, user_pmcs: Sequence[PMC]) -> dict | None:
    form = await get_form(request)
    public_key = form.get("public_key")
    if not public_key:
        raise FlashError("Public key is required")

    # Get selected PMCs from form
    selected_pmcs = form.getlist("selected_pmcs")
    if not selected_pmcs:
        raise FlashError("You must select at least one PMC")

    # Ensure that the selected PMCs are ones of which the user is actually a member
    invalid_pmcs = [pmc for pmc in selected_pmcs if (pmc not in session.committees) and (pmc not in session.projects)]
    if invalid_pmcs:
        raise FlashError(f"Invalid PMC selection: {', '.join(invalid_pmcs)}")

    return await key_user_add(session, public_key, selected_pmcs)


async def key_user_add(session: ClientSession, public_key: str, selected_pmcs: list[str]) -> dict | None:
    if not public_key:
        raise FlashError("Public key is required")

    # Import the key into GPG to validate and extract info
    # TODO: We'll just assume for now that gnupg.GPG() doesn't need to be async
    async with ephemeral_gpg_home() as gpg_home:
        gpg = gnupg.GPG(gnupghome=gpg_home)
        import_result = await asyncio.to_thread(gpg.import_keys, public_key)

        if not import_result.fingerprints:
            raise FlashError("Invalid public key format")

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
        raise FlashError("Failed to import key")
    if (key.get("algo") == "1") and (int(key.get("length", "0")) < 2048):
        # https://infra.apache.org/release-signing.html#note
        # Says that keys must be at least 2048 bits
        raise FlashError("Key is not long enough; must be at least 2048 bits")

    # Store key in database
    async with get_session() as db_session:
        return await key_user_session_add(session, public_key, key, selected_pmcs, db_session)


async def key_user_session_add(
    session: ClientSession,
    public_key: str,
    key: dict,
    selected_pmcs: list[str],
    db_session: AsyncSession,
) -> dict | None:
    # TODO: Check if key already exists
    # psk_statement = select(PublicSigningKey).where(PublicSigningKey.apache_uid == session.uid)

    # # If uncommented, this will prevent a user from adding a second key
    # existing_key = (await db_session.execute(statement)).scalar_one_or_none()
    # if existing_key:
    #     return ("You already have a key registered", None)

    if not session.uid:
        raise FlashError("You must be signed in to add a key")

    fingerprint = key.get("fingerprint")
    if not isinstance(fingerprint, str):
        raise FlashError("Invalid key fingerprint")
    fingerprint = fingerprint.lower()
    uids = key.get("uids")
    async with db_session.begin():
        # Create new key record
        key_record = PublicSigningKey(
            fingerprint=fingerprint,
            algorithm=int(key["algo"]),
            length=int(key.get("length", "0")),
            created=datetime.datetime.fromtimestamp(int(key["date"])),
            expires=datetime.datetime.fromtimestamp(int(key["expires"])) if key.get("expires") else None,
            declared_uid=uids[0] if uids else None,
            apache_uid=session.uid,
            ascii_armored_key=public_key,
        )
        db_session.add(key_record)

        # Link key to selected PMCs
        for pmc_name in selected_pmcs:
            pmc_statement = select(PMC).where(PMC.project_name == pmc_name)
            pmc = (await db_session.execute(pmc_statement)).scalar_one_or_none()
            if pmc and pmc.id:
                link = PMCKeyLink(pmc_id=pmc.id, key_fingerprint=key_record.fingerprint)
                db_session.add(link)
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


@app_route("/keys/add", methods=["GET", "POST"])
@require(Requirements.committer)
async def root_keys_add() -> str:
    """Add a new public signing key to the user's account."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    key_info = None

    # Get PMC objects for all projects the user is a member of
    async with get_session() as db_session:
        from sqlalchemy.sql.expression import ColumnElement

        project_list = session.committees + session.projects
        project_name = cast(ColumnElement[str], PMC.project_name)
        pmc_statement = select(PMC).where(project_name.in_(project_list))
        user_pmcs = (await db_session.execute(pmc_statement)).scalars().all()

    if request.method == "POST":
        try:
            key_info = await key_add_post(session, request, user_pmcs)
        except FlashError as e:
            logging.exception("FlashError:")
            await flash(str(e), "error")
        except Exception as e:
            logging.exception("Exception:")
            await flash(f"Exception: {e}", "error")

    return await render_template(
        "keys-add.html",
        asf_id=session.uid,
        user_pmcs=user_pmcs,
        key_info=key_info,
        algorithms=algorithms,
    )


@app_route("/keys/delete", methods=["POST"])
@require(Requirements.committer)
async def root_keys_delete() -> Response:
    """Delete a public signing key from the user's account."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    form = await get_form(request)
    fingerprint = form.get("fingerprint")
    if not fingerprint:
        await flash("No key fingerprint provided", "error")
        return redirect(url_for("root_keys_review"))

    async with get_session() as db_session:
        async with db_session.begin():
            # Get the key and verify ownership
            psk_statement = select(PublicSigningKey).where(
                PublicSigningKey.fingerprint == fingerprint, PublicSigningKey.apache_uid == session.uid
            )
            key = (await db_session.execute(psk_statement)).scalar_one_or_none()

            if not key:
                await flash("Key not found or not owned by you", "error")
                return redirect(url_for("root_keys_review"))

            # Delete the key
            await db_session.delete(key)

    await flash("Key deleted successfully", "success")
    return redirect(url_for("root_keys_review"))


@app_route("/keys/review")
@require(Requirements.committer)
async def root_keys_review() -> str:
    """Show all keys associated with the user's account."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)

    # Get all existing keys for the user
    async with get_session() as db_session:
        pmcs_loader = selectinload(cast(InstrumentedAttribute[list[PMC]], PublicSigningKey.pmcs))
        psk_statement = select(PublicSigningKey).options(pmcs_loader).where(PublicSigningKey.apache_uid == session.uid)
        user_keys = (await db_session.execute(psk_statement)).scalars().all()

    status_message = request.args.get("status_message")
    status_type = request.args.get("status_type")

    return await render_template(
        "keys-review.html",
        asf_id=session.uid,
        user_keys=user_keys,
        algorithms=algorithms,
        status_message=status_message,
        status_type=status_type,
        now=datetime.datetime.now(datetime.UTC),
    )
