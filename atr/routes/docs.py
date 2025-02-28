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

"""docs.py"""

from quart import render_template, request

from asfquart.auth import Requirements, require
from atr.routes import app_route


@app_route("/docs/verify/<filename>")
@require(Requirements.committer)
async def root_docs_verify(filename: str) -> str:
    """Show verification instructions for an artifact."""
    # Get query parameters
    artifact_sha3 = request.args.get("artifact_sha3", "")
    sha512 = request.args.get("sha512", "")
    has_signature = request.args.get("has_signature", "false").lower() == "true"

    # Return the template
    return await render_template(
        "docs-verify.html",
        filename=filename,
        artifact_sha3=artifact_sha3,
        sha512=sha512,
        has_signature=has_signature,
    )
