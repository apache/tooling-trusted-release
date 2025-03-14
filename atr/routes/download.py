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

import pathlib

import aiofiles
import aiofiles.os
import quart
import werkzeug.wrappers.response as response

import asfquart.auth as auth
import asfquart.base as base
import asfquart.session as session
import atr.db as db
import atr.routes as routes
import atr.util as util


@routes.app_route("/download/<release_key>/<artifact_sha3>")
@auth.require(auth.Requirements.committer)
async def root_download_artifact(release_key: str, artifact_sha3: str) -> response.Response | quart.Response:
    """Download an artifact file."""
    # TODO: This function is very similar to the signature download function
    # We should probably extract the common code into a helper function
    web_session = await session.read()
    if (web_session is None) or (web_session.uid is None):
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    async with db.session() as data:
        # Find the package
        package = await data.package(
            artifact_sha3=artifact_sha3,
            release_key=release_key,
            _release_pmc=True,
        ).get()

        if not package:
            await quart.flash("Artifact not found", "error")
            return quart.redirect(quart.url_for("root_candidate_review"))

        # Check permissions
        if package.release and package.release.pmc:
            if (web_session.uid not in package.release.pmc.pmc_members) and (
                web_session.uid not in package.release.pmc.committers
            ):
                await quart.flash("You don't have permission to download this file", "error")
                return quart.redirect(quart.url_for("root_candidate_review"))

        # Construct file path
        file_path = pathlib.Path(util.get_release_storage_dir()) / artifact_sha3

        # Check that the file exists
        if not await aiofiles.os.path.exists(file_path):
            await quart.flash("Artifact file not found", "error")
            return quart.redirect(quart.url_for("root_candidate_review"))

        # Send the file with original filename
        return await quart.send_file(
            file_path, as_attachment=True, attachment_filename=package.filename, mimetype="application/octet-stream"
        )


@routes.app_route("/download/signature/<release_key>/<signature_sha3>")
@auth.require(auth.Requirements.committer)
async def root_download_signature(release_key: str, signature_sha3: str) -> quart.Response | response.Response:
    """Download a signature file."""
    web_session = await session.read()
    if (web_session is None) or (web_session.uid is None):
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    async with db.session() as data:
        # Find the package that has this signature
        package = await data.package(signature_sha3=signature_sha3, release_key=release_key, _release_pmc=True).get()
        if not package:
            await quart.flash("Signature not found", "error")
            return quart.redirect(quart.url_for("root_candidate_review"))

        # Check permissions
        if package.release and package.release.pmc:
            if (web_session.uid not in package.release.pmc.pmc_members) and (
                web_session.uid not in package.release.pmc.committers
            ):
                await quart.flash("You don't have permission to download this file", "error")
                return quart.redirect(quart.url_for("root_candidate_review"))

        # Construct file path
        file_path = pathlib.Path(util.get_release_storage_dir()) / signature_sha3

        # Check that the file exists
        if not await aiofiles.os.path.exists(file_path):
            await quart.flash("Signature file not found", "error")
            return quart.redirect(quart.url_for("root_candidate_review"))

        # Send the file with original filename and .asc extension
        return await quart.send_file(
            file_path,
            as_attachment=True,
            attachment_filename=f"{package.filename}.asc",
            mimetype="application/pgp-signature",
        )
