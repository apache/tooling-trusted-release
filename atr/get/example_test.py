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

import atr.blueprints.get as get
import atr.forms as forms
import atr.post as post
import atr.util as util
import atr.web as web


@get.committer("/example/test")
async def respond(session: web.Committer) -> str:
    empty_form = await forms.Empty.create_form()
    return f"""\
<h1>Test route (GET)</h1>
<p>Hello, {session.asf_uid}!</p>
<p>This is a test GET route for committers only.</p>

<h2>Test POST submission</h2>
<form method="post" action="{util.as_url(post.example_test)}">
    {empty_form.hidden_tag()}
    <button type="submit" class="btn btn-primary">Submit to POST route</button>
</form>
"""
