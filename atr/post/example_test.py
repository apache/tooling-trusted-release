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

import quart

import atr.blueprints.post as post
import atr.get as get
import atr.util as util
import atr.web as web


@post.committer("/example/test")
async def respond(session: web.Committer) -> quart.Response:
    await util.validate_empty_form()
    await quart.flash("POST request successful!", "success")

    return quart.Response(
        f"""\
<h1>Test route (POST)</h1>
<p>Hello, {session.asf_uid}!</p>
<p>This POST route was successfully called!</p>
<p><a href="{util.as_url(get.example_test)}">Go back to the GET route</a></p>
""",
        mimetype="text/html",
    )
