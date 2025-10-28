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

from collections.abc import Awaitable, Callable

import quart.wrappers.response as quart_response
import werkzeug.wrappers.response as response

import atr.blueprints.post as post
import atr.shared as shared
import atr.web as web

type Respond = Callable[[int, str], Awaitable[tuple[quart_response.Response, int] | response.Response]]


@post.committer("/finish/<project_name>/<version_name>")
async def selected(
    session: web.Committer, project_name: str, version_name: str
) -> tuple[quart_response.Response, int] | response.Response | str:
    """Finish a release preview."""
    return await shared.finish.selected(session, project_name, version_name)
