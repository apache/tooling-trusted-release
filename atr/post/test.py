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
import atr.log as log
import atr.shared as shared
import atr.web as web


@post.public("/test/empty")
@post.empty()
async def test_empty(session: web.Committer | None) -> web.WerkzeugResponse:
    msg = "Empty form submitted successfully"
    log.info(msg)
    await quart.flash(msg, "success")
    return await web.redirect(get.test.test_empty)


@post.public("/test/multiple")
@post.form(shared.test.MultipleForm)
async def test_multiple(session: web.Committer | None, form: shared.test.MultipleForm) -> web.WerkzeugResponse:
    match form:
        case shared.test.AppleForm() as apple:
            msg = f"Apple order received: variety={apple.variety}, quantity={apple.quantity}, organic={apple.organic}"
            log.info(msg)
            await quart.flash(msg, "success")

        case shared.test.BananaForm() as banana:
            msg = f"Banana order received: ripeness={banana.ripeness}, bunch_size={banana.bunch_size}"
            log.info(msg)
            await quart.flash(msg, "success")

    return await web.redirect(get.test.test_multiple)


@post.public("/test/single")
@post.form(shared.test.SingleForm)
async def test_single(session: web.Committer | None, form: shared.test.SingleForm) -> web.WerkzeugResponse:
    file_names = [f.filename for f in form.files] if form.files else []
    compatibility_names = [f.value for f in form.compatibility] if form.compatibility else []
    if (form.message == "Forbidden message!") and (session is not None):
        return await session.form_error(
            "message",
            "You are not permitted to submit the forbidden message",
        )
    msg = (
        f"Single form received:"
        f" name={form.name},"
        f" email={form.email},"
        f" message={form.message},"
        f" files={file_names},"
        f" compatibility={compatibility_names},"
        f" vote={form.vote}"
    )
    log.info(msg)
    await quart.flash(msg, "success")

    return await web.redirect(get.test.test_single)
