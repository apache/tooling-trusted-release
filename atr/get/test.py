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
import atr.form as form
import atr.get.root as root
import atr.htm as htm
import atr.shared as shared
import atr.template as template
import atr.web as web


@get.public("/test/empty")
async def test_empty(session: web.Committer | None) -> str:
    empty_form = form.render(
        model_cls=form.Empty,
        submit_label="Submit empty form",
        action="/test/empty",
    )

    forms_html = htm.div[
        htm.h2["Empty form"],
        htm.p["This form only validates the CSRF token and contains no other fields."],
        empty_form,
    ]

    return await template.blank(title="Test empty form", content=forms_html)


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


@get.public("/test/multiple")
async def test_multiple(session: web.Committer | None) -> str:
    apple_form = form.render(
        model_cls=shared.test.AppleForm,
        submit_label="Order apples",
        action="/test/multiple",
    )

    banana_form = form.render(
        model_cls=shared.test.BananaForm,
        submit_label="Order bananas",
        action="/test/multiple",
    )

    forms_html = htm.div[
        htm.h2["Apple order form"],
        apple_form,
        htm.h2["Banana order form"],
        banana_form,
    ]

    return await template.blank(title="Test multiple forms", content=forms_html)


@get.public("/test/single")
async def test_single(session: web.Committer | None) -> str:
    import htpy

    vote_widget = htpy.div(class_="btn-group", role="group")[
        htpy.input(type="radio", class_="btn-check", name="vote", id="vote_0", value="+1", autocomplete="off"),
        htpy.label(class_="btn btn-outline-success", for_="vote_0")["+1"],
        htpy.input(type="radio", class_="btn-check", name="vote", id="vote_1", value="0", autocomplete="off"),
        htpy.label(class_="btn btn-outline-secondary", for_="vote_1")["0"],
        htpy.input(type="radio", class_="btn-check", name="vote", id="vote_2", value="-1", autocomplete="off"),
        htpy.label(class_="btn btn-outline-danger", for_="vote_2")["-1"],
    ]

    single_form = form.render(
        model_cls=shared.test.SingleForm,
        submit_label="Submit",
        action="/test/single",
        custom={"vote": vote_widget},
    )

    forms_html = htm.div[
        htm.h2["Single form"],
        single_form,
    ]

    return await template.blank(title="Test single form", content=forms_html)
