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

import dataclasses
import enum
from typing import TYPE_CHECKING, Any, Final, Literal, TypeVar

import markupsafe
import quart_wtf
import quart_wtf.typing
import wtforms

import atr.htm as htm

if TYPE_CHECKING:
    from collections.abc import Callable

EMAIL: Final = wtforms.validators.Email()
REQUIRED: Final = wtforms.validators.InputRequired()
REQUIRED_DATA: Final = wtforms.validators.DataRequired()
OPTIONAL: Final = wtforms.validators.Optional()

# Match _Choice in the wtforms.fields.choices stub
# typeshed-fallback/stubs/WTForms/wtforms/fields/choices.pyi
type Choice = tuple[Any, str] | tuple[Any, str, dict[str, Any]]
type Choices = list[Choice]


E = TypeVar("E", bound=enum.Enum)


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


@dataclasses.dataclass
class Elements:
    hidden: list[markupsafe.Markup]
    fields: list[tuple[markupsafe.Markup, markupsafe.Markup]]
    submit: markupsafe.Markup | None


class Empty(Typed):
    pass


class Hidden(Typed):
    hidden_field = wtforms.HiddenField()
    submit = wtforms.SubmitField()


class Submit(Typed):
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


def checkbox(
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


def enumeration[E: enum.Enum](enum_cls: type[E]) -> list[tuple[str, str]]:
    return [(member.name, member.value.name) for member in enum_cls]


def enumeration_coerce[E: enum.Enum](enum_cls: type[E]) -> Callable[[Any], E | None]:
    def coerce(value: Any) -> E | None:
        if isinstance(value, enum_cls):
            return value
        if value in (None, ""):
            return None
        try:
            return enum_cls[value]
        except KeyError as exc:
            raise ValueError(value) from exc

    return coerce


def error(field: wtforms.Field, message: str) -> Literal[False]:
    if not isinstance(field.errors, list):
        try:
            field.errors = list(field.errors)
        except Exception:
            field.errors = []
    field.errors.append(message)
    return False


def clear_errors(field: wtforms.Field) -> None:
    if not isinstance(field.errors, list):
        try:
            field.errors = list(field.errors)
        except Exception:
            field.errors = []
    field.errors[:] = []
    entries = getattr(field, "entries", None)
    if isinstance(entries, list):
        for entry in entries:
            entry_errors = getattr(entry, "errors", None)
            if isinstance(entry_errors, list):
                entry_errors[:] = []
            else:
                setattr(entry, "errors", [])


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


def render_columns(
    form: Typed,
    action: str,
    form_classes: str = ".atr-canary",
    submit_classes: str = "btn-primary",
    descriptions: bool = False,
) -> htm.Element:
    label_classes = "col-sm-3 col-form-label text-sm-end"
    elements = _render_elements(
        form,
        label_classes=label_classes,
        submit_classes=submit_classes,
        descriptions=descriptions,
    )

    field_rows: list[htm.Element] = []
    for label, widget in elements.fields:
        row_div = htm.div(".mb-3.row")
        widget_div = htm.div(".col-sm-8")
        field_rows.append(row_div[label, widget_div[widget]])

    form_children: list[htm.Element | markupsafe.Markup] = elements.hidden + field_rows

    if elements.submit is not None:
        submit_div = htm.div(".col-sm-9.offset-sm-3")
        submit_row = htm.div(".row")[submit_div[elements.submit]]
        form_children.append(submit_row)

    return htm.form(form_classes, action=action, method="post")[form_children]


def render_simple(
    form: Typed,
    action: str,
    form_classes: str = "",
    submit_classes: str = "btn-primary",
    descriptions: bool = False,
) -> htm.Element:
    elements = _render_elements(form, submit_classes=submit_classes, descriptions=descriptions)

    field_rows: list[htm.Element] = []
    for label, widget in elements.fields:
        row_div = htm.div[label, widget]
        field_rows.append(row_div)

    form_children: list[htm.Element | markupsafe.Markup] = []
    form_children.extend(elements.hidden)
    form_children.append(htm.div[field_rows])

    if elements.submit is not None:
        submit_row = htm.p[elements.submit]
        form_children.append(submit_row)

    return htm.form(form_classes, action=action, method="post")[form_children]


def render_table(
    form: Typed,
    action: str,
    form_classes: str = "",
    table_classes: str = ".table.table-striped.table-bordered",
    submit_classes: str = "btn-primary",
    descriptions: bool = False,
) -> htm.Element:
    # Small elements in Bootstrap
    elements = _render_elements(form, submit_classes=submit_classes, small=True, descriptions=descriptions)

    field_rows: list[htm.Element] = []
    for label, widget in elements.fields:
        row_tr = htm.tr[htm.th[label], htm.td[widget]]
        field_rows.append(row_tr)

    form_children: list[htm.Element | markupsafe.Markup] = []
    form_children.extend(elements.hidden)
    form_children.append(htm.table(table_classes)[htm.tbody[field_rows]])

    if elements.submit is not None:
        submit_row = htm.p[elements.submit]
        form_children.append(submit_row)

    return htm.form(form_classes, action=action, method="post")[form_children]


def select(
    label: str, optional: bool = False, validators: list[Any] | None = None, **kwargs: Any
) -> wtforms.SelectField:
    if validators is None:
        validators = []
    if optional is False:
        validators.append(REQUIRED)
    else:
        validators.append(OPTIONAL)
    if "choices" in kwargs:
        # https://github.com/pallets-eco/wtforms/issues/338
        if isinstance(kwargs["choices"], type) and issubclass(kwargs["choices"], enum.Enum):
            enum_cls = kwargs["choices"]
            kwargs["choices"] = enumeration(enum_cls)
            kwargs["coerce"] = enumeration_coerce(enum_cls)
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


def submit(label: str = "Submit", **kwargs: Any) -> wtforms.SubmitField:
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
    placeholder: str | None = None,
    **kwargs: Any,
) -> wtforms.URLField:
    if validators is None:
        validators = [wtforms.validators.URL()]
    if optional is False:
        validators.append(REQUIRED)
    else:
        validators.append(OPTIONAL)
    if placeholder is not None:
        if "render_kw" not in kwargs:
            kwargs["render_kw"] = {}
        kwargs["render_kw"]["placeholder"] = placeholder
    return wtforms.URLField(label, validators=validators, **kwargs)


def _render_elements(
    form: Typed,
    label_classes: str = "col-sm-3 col-form-label text-sm-end",
    submit_classes: str = "btn-primary",
    small: bool = False,
    descriptions: bool = False,
) -> Elements:
    hidden_elements: list[markupsafe.Markup] = []
    field_elements: list[tuple[markupsafe.Markup, markupsafe.Markup]] = []
    submit_element: markupsafe.Markup | None = None

    for field in form:
        if isinstance(field, wtforms.HiddenField):
            hidden_elements.append(markupsafe.Markup(str(field)))
            continue

        if isinstance(field, wtforms.StringField) or isinstance(field, wtforms.SelectField):
            label = markupsafe.Markup(str(field.label(class_=label_classes)))

            widget_class = "form-control" if isinstance(field, wtforms.StringField) else "form-select"
            widget_classes = widget_class if (small is False) else f"{widget_class}-sm"
            if field.errors:
                widget_classes += " is-invalid"
            widget = markupsafe.Markup(str(field(class_=widget_classes)))

            if field.errors:
                joined_errors = " ".join(field.errors)
                div = htm.div(".invalid-feedback.d-block")[joined_errors]
                widget += markupsafe.Markup(str(div))

            if descriptions is True and field.description:
                desc = htm.div(".form-text.text-muted")[str(field.description)]
                widget += markupsafe.Markup(str(desc))

            field_elements.append((label, widget))
            continue

        # wtforms.SubmitField is a subclass of wtforms.BooleanField
        # So we need to check for it before BooleanField
        if isinstance(field, wtforms.SubmitField):
            button_class = "btn " + submit_classes
            submit_element = markupsafe.Markup(str(field(class_=button_class)))
            continue

        if isinstance(field, wtforms.BooleanField):
            # Replacing col-form-label with form-check-label moves the label up
            # This aligns it properly with the checkbox
            # TODO: Move the widget down instead of the label up
            classes = label_classes.replace("col-form-label", "form-check-label")
            label = markupsafe.Markup(str(field.label(class_=classes)))
            widget = markupsafe.Markup(str(field(class_="form-check-input")))
            field_elements.append((label, widget))
            # TODO: Errors and description
            continue

        raise TypeError(f"Unsupported field type: {type(field).__name__}")

    return Elements(hidden_elements, field_elements, submit_element)
