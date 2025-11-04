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


import atr.blueprints.post as post
import atr.jwtoken as jwtoken
import atr.shared as shared
import atr.util as util
import atr.web as web


@post.committer("/tokens/jwt")
async def jwt_post(session: web.Committer) -> web.QuartResponse:
    await util.validate_empty_form()

    jwt_token = jwtoken.issue(session.uid)
    return web.TextResponse(jwt_token)


@post.committer("/tokens")
async def tokens(session: web.Committer) -> str | web.WerkzeugResponse:
    return await shared.tokens.tokens(session)
