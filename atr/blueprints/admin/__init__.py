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

"""Any routes related to the admin interface of the ATR."""

from typing import Final

import asfquart.auth as auth
import asfquart.base as base
import asfquart.session as session
import quart

import atr.util as util

BLUEPRINT: Final = quart.Blueprint("admin", __name__, url_prefix="/admin", template_folder="templates")


@BLUEPRINT.before_request
async def before_request_func() -> None:
    @auth.require(auth.Requirements.committer)
    async def check_logged_in() -> None:
        web_session = await session.read()
        if web_session is None:
            raise base.ASFQuartException("Not authenticated", errorcode=401)

        if web_session.uid not in util.get_admin_users():
            raise base.ASFQuartException("You are not authorized to access the admin interface", errorcode=403)

    await check_logged_in()
