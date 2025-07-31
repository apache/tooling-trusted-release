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

from __future__ import annotations

from typing import Any, TypeVar

import quart_wtf
import quart_wtf.typing
import wtforms


class Typed(quart_wtf.QuartForm):
    """Quart form with type annotations."""

    csrf_token = wtforms.HiddenField()

    @classmethod
    async def create_form(
        cls: type[F],
        formdata: object | quart_wtf.typing.FormData = quart_wtf.form._Auto,
        obj: Any | None = None,
        prefix: str = "",
        data: dict | None = None,
        meta: dict | None = None,
        **kwargs: dict[str, Any],
    ) -> F:
        """Create a form instance with typing."""
        form = await super().create_form(formdata, obj, prefix, data, meta, **kwargs)
        if not isinstance(form, cls):
            raise TypeError(f"Form is not of type {cls.__name__}")
        return form


F = TypeVar("F", bound=Typed)


class Empty(Typed):
    pass


class Hidden(Typed):
    hidden_field = wtforms.HiddenField()
    submit = wtforms.SubmitField()


class Value(Typed):
    value = wtforms.StringField(validators=[wtforms.validators.InputRequired()])
    submit = wtforms.SubmitField()


# TODO: No shared class for Validators?
def string(label: str, validators: list[Any] | None = None, **kwargs: Any) -> wtforms.StringField:
    if validators is None:
        validators = [wtforms.validators.InputRequired()]
    return wtforms.StringField(label, validators=validators, **kwargs)
