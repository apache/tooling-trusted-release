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

import enum
from typing import Annotated, Literal

import pydantic

import atr.form as form

type APPLE = Literal["apple"]
type BANANA = Literal["banana"]


class Compatibility(enum.Enum):
    Alpha = "Alpha"
    Beta = "Beta"
    Gamma = "Gamma"


class AppleForm(form.Form):
    variant: APPLE = form.value(APPLE)
    variety: Literal["Granny Smith", "Honeycrisp", "Gala"] = form.label("Apple variety")
    quantity: form.Int = form.label("Number of apples")
    organic: form.Bool = form.label("Organic?")


class BananaForm(form.Form):
    variant: BANANA = form.value(BANANA)
    ripeness: Literal["Green", "Yellow", "Brown"] = form.label("Ripeness level", widget=form.Widget.RADIO)
    bunch_size: form.Int = form.label("Number of bananas in bunch")


type MultipleForm = Annotated[
    AppleForm | BananaForm,
    form.DISCRIMINATOR,
]


class SingleForm(form.Form):
    name: str = form.label("Full name")
    email: form.Email = form.label("Email address")
    message: str = form.label("Message")
    files: form.FileList = form.label("Files to upload")
    compatibility: form.Set[Compatibility] = form.label("Compatibility")
    vote: Literal["+1", "0", "-1"] = form.label("Vote", widget=form.Widget.CUSTOM)

    @pydantic.field_validator("email")
    @classmethod
    def validate_email(cls, value: str, info: pydantic.ValidationInfo) -> str:
        if value == "":
            return value

        session = form.session(info)

        if session is None:
            return value

        expected_email = f"{session.asf_uid}@apache.org"
        if value != expected_email:
            raise ValueError(f"Email must be empty or {expected_email}")

        return value
