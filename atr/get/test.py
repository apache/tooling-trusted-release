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

import asfquart.base as base
import asfquart.session

import atr.blueprints.get as get
import atr.config as config
import atr.get.root as root
import atr.web as web


@get.public("/test/login")
async def test_login(session: web.Committer | None) -> web.WerkzeugResponse:
    if not config.get().ALLOW_TESTS:
        raise base.ASFQuartException("Test login not enabled", errorcode=404)

    session_data = {
        "uid": "test",
        "fullname": "Test User",
        "committees": ["test"],
        "projects": ["test"],
        "isMember": False,
        "isChair": False,
        "isRole": False,
        "metadata": {},
    }

    asfquart.session.write(session_data)
    return await web.redirect(root.index)
