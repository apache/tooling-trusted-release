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

"""project.py"""

import http.client

import quart

import atr.db as db
import atr.db.models as models
import atr.routes as routes


@routes.public("/committees")
async def directory() -> str:
    """Main committee directory page."""
    async with db.session() as data:
        committees = await data.committee(_projects=True).order_by(models.Committee.name).all()
        return await quart.render_template("committee-directory.html", committees=committees)


@routes.public("/committees/<name>")
async def view(name: str) -> str:
    async with db.session() as data:
        committee = await data.committee(name=name, _projects=True, _public_signing_keys=True).demand(
            http.client.HTTPException(404)
        )
        return await quart.render_template("committee-view.html", committee=committee, algorithms=routes.algorithms)
