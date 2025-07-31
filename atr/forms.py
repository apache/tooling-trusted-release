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

from typing import Any, Final, TypeVar

import htpy
import markupsafe
import quart_wtf
import quart_wtf.typing
import wtforms

EMAIL: Final = wtforms.validators.Email()
REQUIRED: Final = wtforms.validators.InputRequired()
REQUIRED_DATA: Final = wtforms.validators.DataRequired()
OPTIONAL: Final = wtforms.validators.Optional()

# Match _Choice in the wtforms.fields.choices stub
# typeshed-fallback/stubs/WTForms/wtforms/fields/choices.pyi
type Choice = tuple[Any, str] | tuple[Any, str, dict[str, Any]]
type Choices = list[Choice]


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
    value = wtforms.StringField(validators=[REQUIRED])
    submit = wtforms.SubmitField()


def boolean(
    label: str, optional: bool = False, validators: list[Any] | None = None, **kwargs: Any
) -> wtforms.BooleanField:
    if validators is None:
        validators = []
    if optional is False:
        validators.append(REQUIRED_DATA)
    else:
        validators.append(OPTIONAL)
    return wtforms.BooleanField(label, **kwargs)


def checkboxes(
    label: str, optional: bool = False, validators: list[Any] | None = None, **kwargs: Any
) -> wtforms.SelectMultipleField:
    if validators is None:
        validators = []
    if optional is False:
        validators.append(REQUIRED)
    else:
        validators.append(OPTIONAL)
    return wtforms.SelectMultipleField(
        label,
        validators=validators,
        coerce=str,
        option_widget=wtforms.widgets.CheckboxInput(),
        widget=wtforms.widgets.ListWidget(prefix_label=False),
        **kwargs,
    )


def choices(
    field: wtforms.RadioField | wtforms.SelectMultipleField, choices: Choices, default: str | None = None
) -> None:
    field.choices = choices
    # Form construction calls Field.process
    # This sets data = self.default() or self.default
    # Then self.object_data = data
    # Then calls self.process_data(data) which sets self.data = data
    # And SelectField.iter_choices reads self.data for the default
    if isinstance(field, wtforms.RadioField):
        if default is not None:
            field.data = default


def constant(value: str) -> list[wtforms.validators.InputRequired | wtforms.validators.Regexp]:
    return [REQUIRED, wtforms.validators.Regexp(value, message=f"You must enter {value!r} in this field")]


def file(label: str, optional: bool = False, validators: list[Any] | None = None, **kwargs: Any) -> wtforms.FileField:
    if validators is None:
        validators = []
    if optional is False:
        validators.append(REQUIRED)
    else:
        validators.append(OPTIONAL)
    return wtforms.FileField(label, validators=validators, **kwargs)


def files(
    label: str, optional: bool = False, validators: list[Any] | None = None, **kwargs: Any
) -> wtforms.MultipleFileField:
    if validators is None:
        validators = []
    if optional is False:
        validators.append(REQUIRED)
    else:
        validators.append(OPTIONAL)
    return wtforms.MultipleFileField(label, validators=validators, **kwargs)


def hidden(optional: bool = False, validators: list[Any] | None = None, **kwargs: Any) -> wtforms.HiddenField:
    if validators is None:
        validators = []
    if optional is False:
        validators.append(REQUIRED)
    else:
        validators.append(OPTIONAL)
    return wtforms.HiddenField(validators=validators, **kwargs)


def integer(
    label: str, optional: bool = False, validators: list[Any] | None = None, **kwargs: Any
) -> wtforms.IntegerField:
    if validators is None:
        validators = []
    if optional is False:
        validators.append(REQUIRED)
    else:
        validators.append(OPTIONAL)
    return wtforms.IntegerField(label, validators=validators, **kwargs)


def length(min: int | None = None, max: int | None = None) -> list[wtforms.validators.Length]:
    validators = []
    if min is not None:
        validators.append(wtforms.validators.Length(min=min))
    if max is not None and max > 0:
        validators.append(wtforms.validators.Length(max=max))
    return validators


# TODO: Do we need this?
def multiple(label: str, validators: list[Any] | None = None, **kwargs: Any) -> wtforms.SelectMultipleField:
    if validators is None:
        validators = [REQUIRED]
    return wtforms.SelectMultipleField(label, validators=validators, **kwargs)


def optional(label: str, **kwargs: Any) -> wtforms.StringField:
    return string(label, optional=True, **kwargs)


def radio(label: str, optional: bool = False, validators: list[Any] | None = None, **kwargs: Any) -> wtforms.RadioField:
    # Choices and default must be set at runtime
    if validators is None:
        validators = []
    if optional is False:
        validators.append(REQUIRED)
    else:
        validators.append(OPTIONAL)
    return wtforms.RadioField(label, validators=validators, **kwargs)


def render(form: Typed, action: str) -> htpy.Element:
    hidden_elems: list[markupsafe.Markup] = []
    field_rows: list[htpy.Element] = []
    submit_row: htpy.Element | None = None

    for field in form:
        if isinstance(field, wtforms.HiddenField):
            hidden_elems.append(markupsafe.Markup(str(field)))
            continue
        if isinstance(field, wtforms.StringField):
            widget = markupsafe.Markup(str(field(class_="form-control")))
            label_html = markupsafe.Markup(str(field.label(class_="col-sm-3 col-form-label text-sm-end")))
            row = htpy.div(".mb-3 row")[label_html, htpy.div(".col-sm-8")[widget]]
            field_rows.append(row)
            continue
        if isinstance(field, wtforms.SelectField):
            widget = markupsafe.Markup(str(field(class_="form-select")))
            label_html = markupsafe.Markup(str(field.label(class_="col-sm-3 col-form-label text-sm-end")))
            row = htpy.div(".mb-3 row")[label_html, htpy.div(".col-sm-8")[widget]]
            field_rows.append(row)
            continue
        if isinstance(field, wtforms.SubmitField):
            button_html = markupsafe.Markup(str(field(class_="btn btn-primary mt-2")))
            submit_row = htpy.div(".row")[htpy.div(".col-sm-9 offset-sm-3")[button_html]]
            continue
        raise TypeError(f"Unsupported field type: {type(field).__name__}")

    form_children: list[htpy.Element | markupsafe.Markup] = hidden_elems + field_rows
    if submit_row is not None:
        form_children.append(submit_row)

    return htpy.form(".atr-canary", action=action, method="post")[form_children]


def select(
    label: str, optional: bool = False, validators: list[Any] | None = None, **kwargs: Any
) -> wtforms.SelectField:
    if validators is None:
        validators = []
    if optional is False:
        validators.append(REQUIRED)
    else:
        validators.append(OPTIONAL)
    return wtforms.SelectField(label, validators=validators, **kwargs)


# TODO: No shared class for Validators?
def string(
    label: str,
    optional: bool = False,
    validators: list[Any] | None = None,
    placeholder: str | None = None,
    **kwargs: Any,
) -> wtforms.StringField:
    if validators is None:
        validators = []
    if optional is False:
        validators.append(REQUIRED)
    else:
        validators.append(OPTIONAL)
    if placeholder is not None:
        if "render_kw" not in kwargs:
            kwargs["render_kw"] = {}
        kwargs["render_kw"]["placeholder"] = placeholder
    return wtforms.StringField(label, validators=validators, **kwargs)


def submit(label: str, **kwargs: Any) -> wtforms.SubmitField:
    return wtforms.SubmitField(label, **kwargs)


def textarea(
    label: str,
    optional: bool = False,
    validators: list[Any] | None = None,
    placeholder: str | None = None,
    rows: int | None = None,
    **kwargs: Any,
) -> wtforms.TextAreaField:
    if validators is None:
        validators = []
    if optional is False:
        validators.append(REQUIRED)
    else:
        validators.append(OPTIONAL)
    if placeholder is not None:
        if "render_kw" not in kwargs:
            kwargs["render_kw"] = {}
        kwargs["render_kw"]["placeholder"] = placeholder
    if rows is not None:
        if "render_kw" not in kwargs:
            kwargs["render_kw"] = {}
        kwargs["render_kw"]["rows"] = rows
    return wtforms.TextAreaField(label, validators=validators, **kwargs)


def url(
    label: str,
    optional: bool = False,
    validators: list[Any] | None = None,
    **kwargs: Any,
) -> wtforms.URLField:
    if validators is None:
        validators = [wtforms.validators.URL()]
    if optional is False:
        validators.append(REQUIRED)
    else:
        validators.append(OPTIONAL)
    return wtforms.URLField(label, validators=validators, **kwargs)
