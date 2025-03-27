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

"""preview.py"""

import asfquart
import quart

import atr.db as db
import atr.db.models as models
import atr.routes as routes

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")


@routes.committer("/preview/review")
async def review(session: routes.CommitterSession) -> str:
    """Show all release previews to which the user has access."""
    async with db.session() as data:
        # Get all releases where the user is a PMC member or committer
        releases = await data.release(
            stage=models.ReleaseStage.RELEASE,
            phase=models.ReleasePhase.RELEASE_PREVIEW,
            _committee=True,
            _packages=True,
        ).all()

    # Filter to only show releases for PMCs or PPMCs where the user is a member or committer
    user_previews = []
    for r in releases:
        if r.committee is None:
            continue
        # For PPMCs the "members" are stored in the committers field
        if (session.uid in r.committee.committee_members) or (session.uid in r.committee.committers):
            user_previews.append(r)

    return await quart.render_template(
        "preview-review.html",
        previews=user_previews,
    )
