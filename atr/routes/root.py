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

"""root.py"""

import asfquart.session
import quart
import werkzeug.wrappers.response as response

import atr.routes as routes


@routes.public("/")
async def index() -> response.Response | str:
    """Main page."""
    if await asfquart.session.read():
        return await quart.render_template("index-committer.html")
    return await quart.render_template("index-public.html")


@routes.public("/tutorial")
async def tutorial() -> str:
    """Tutorial page."""
    return await quart.render_template("tutorial.html")
