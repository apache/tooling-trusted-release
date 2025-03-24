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
import asfquart.auth as auth
import asfquart.base as base
import asfquart.session as session
import quart
import werkzeug.wrappers.response as response

import atr.routes as routes
import atr.util as util


@routes.app_route("/download/<phase>/<project>/<version>/<path>")
@auth.require(auth.Requirements.committer)
async def root_download(
    phase: str, project: str, version: str, path: pathlib.Path
) -> response.Response | quart.Response:
    """Download a file from a release in any phase."""
    web_session = await session.read()
    if (web_session is None) or (web_session.uid is None):
        raise base.ASFQuartException("Not authenticated", errorcode=401)

    # Check that path is relative
    path = pathlib.Path(path)
    if not path.is_relative_to(path.anchor):
        raise routes.FlashError("Path must be relative")

    file_path = util.get_phase_dir() / phase / project / version / path

    # Check that the file exists
    if not await aiofiles.os.path.exists(file_path):
        await quart.flash("File not found", "error")
        return quart.redirect(quart.url_for("root_candidate_review"))

    # Send the file with original filename
    return await quart.send_file(
        file_path, as_attachment=True, attachment_filename=path.name, mimetype="application/octet-stream"
    )
