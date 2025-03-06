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

"""download.py"""

from pathlib import Path
from typing import cast

import aiofiles
import aiofiles.os
from quart import flash, redirect, send_file, url_for
from quart.wrappers.response import Response as QuartResponse
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlmodel import select
from werkzeug.wrappers.response import Response

from asfquart.auth import Requirements, require
from asfquart.base import ASFQuartException
from asfquart.session import read as session_read
from atr.db import create_async_db_session
from atr.db.models import (
    PMC,
    Package,
    Release,
)
from atr.routes import app_route
from atr.util import get_release_storage_dir


@app_route("/download/<release_key>/<artifact_sha3>")
@require(Requirements.committer)
async def root_download_artifact(release_key: str, artifact_sha3: str) -> Response | QuartResponse:
    """Download an artifact file."""
    # TODO: This function is very similar to the signature download function
    # We should probably extract the common code into a helper function
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    async with create_async_db_session() as db_session:
        # Find the package
        package_release = selectinload(cast(InstrumentedAttribute[Release], Package.release))
        release_pmc = package_release.selectinload(cast(InstrumentedAttribute[PMC], Release.pmc))
        package_statement = (
            select(Package)
            .where(Package.artifact_sha3 == artifact_sha3, Package.release_key == release_key)
            .options(release_pmc)
        )
        result = await db_session.execute(package_statement)
        package = result.scalar_one_or_none()

        if not package:
            await flash("Artifact not found", "error")
            return redirect(url_for("root_candidate_review"))

        # Check permissions
        if package.release and package.release.pmc:
            if (session.uid not in package.release.pmc.pmc_members) and (
                session.uid not in package.release.pmc.committers
            ):
                await flash("You don't have permission to download this file", "error")
                return redirect(url_for("root_candidate_review"))

        # Construct file path
        file_path = Path(get_release_storage_dir()) / artifact_sha3

        # Check that the file exists
        if not await aiofiles.os.path.exists(file_path):
            await flash("Artifact file not found", "error")
            return redirect(url_for("root_candidate_review"))

        # Send the file with original filename
        return await send_file(
            file_path, as_attachment=True, attachment_filename=package.filename, mimetype="application/octet-stream"
        )


@app_route("/download/signature/<release_key>/<signature_sha3>")
@require(Requirements.committer)
async def root_download_signature(release_key: str, signature_sha3: str) -> QuartResponse | Response:
    """Download a signature file."""
    session = await session_read()
    if (session is None) or (session.uid is None):
        raise ASFQuartException("Not authenticated", errorcode=401)

    async with create_async_db_session() as db_session:
        # Find the package that has this signature
        package_release = selectinload(cast(InstrumentedAttribute[Release], Package.release))
        release_pmc = package_release.selectinload(cast(InstrumentedAttribute[PMC], Release.pmc))
        package_statement = (
            select(Package)
            .where(Package.signature_sha3 == signature_sha3, Package.release_key == release_key)
            .options(release_pmc)
        )
        result = await db_session.execute(package_statement)
        package = result.scalar_one_or_none()

        if not package:
            await flash("Signature not found", "error")
            return redirect(url_for("root_candidate_review"))

        # Check permissions
        if package.release and package.release.pmc:
            if (session.uid not in package.release.pmc.pmc_members) and (
                session.uid not in package.release.pmc.committers
            ):
                await flash("You don't have permission to download this file", "error")
                return redirect(url_for("root_candidate_review"))

        # Construct file path
        file_path = Path(get_release_storage_dir()) / signature_sha3

        # Check that the file exists
        if not await aiofiles.os.path.exists(file_path):
            await flash("Signature file not found", "error")
            return redirect(url_for("root_candidate_review"))

        # Send the file with original filename and .asc extension
        return await send_file(
            file_path,
            as_attachment=True,
            attachment_filename=f"{package.filename}.asc",
            mimetype="application/pgp-signature",
        )
