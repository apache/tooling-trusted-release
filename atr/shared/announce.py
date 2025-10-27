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

from typing import Any

import atr.forms as forms
import atr.util as util


class Form(forms.Typed):
    """Form for announcing a release preview."""

    preview_name = forms.hidden()
    preview_revision = forms.hidden()
    mailing_list = forms.radio("Send vote email to")
    download_path_suffix = forms.optional("Download path suffix")
    confirm_announce = forms.boolean("Confirm")
    subject = forms.optional("Subject")
    body = forms.textarea("Body", optional=True)
    submit = forms.submit("Send announcement email")


async def create_form(permitted_recipients: list[str], *, data: dict[str, Any] | None = None) -> Form:
    """Create and return an instance of the announce form."""

    mailing_list_choices: forms.Choices = sorted([(recipient, recipient) for recipient in permitted_recipients])
    mailing_list_default = util.USER_TESTS_ADDRESS

    form_instance = await Form.create_form(data=data)
    forms.choices(
        form_instance.mailing_list,
        mailing_list_choices,
        mailing_list_default,
    )
    return form_instance
