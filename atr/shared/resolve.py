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

from typing import Annotated, Literal

import atr.form as form

type SUBMIT = Literal["submit"]
type TABULATE = Literal["tabulate"]


class SubmitForm(form.Form):
    variant: SUBMIT = form.value(SUBMIT)
    email_body: str = form.label("Email body", widget=form.Widget.TEXTAREA)
    vote_result: Literal["Passed", "Failed"] = form.label("Vote result", widget=form.Widget.RADIO)


class TabulateForm(form.Empty):
    variant: TABULATE = form.value(TABULATE)


type ResolveForm = Annotated[
    SubmitForm | TabulateForm,
    form.DISCRIMINATOR,
]
