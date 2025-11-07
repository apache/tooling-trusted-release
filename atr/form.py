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

import enum
import json
import types
from typing import TYPE_CHECKING, Annotated, Any, Final, Literal, get_args, get_origin

import htpy
import pydantic
import pydantic.functional_validators as functional_validators
import quart
import quart.datastructures as datastructures
import quart_wtf.utils as utils

import atr.htm as htm
import atr.models.schema as schema

if TYPE_CHECKING:
    from collections.abc import Iterator

    import markupsafe
    import pydantic_core

    import atr.web as web

DISCRIMINATOR_NAME: Final[str] = "variant"
DISCRIMINATOR: Final[Any] = schema.discriminator(DISCRIMINATOR_NAME)


class Form(schema.Form):
    pass


class Empty(Form):
    pass


class Widget(enum.Enum):
    CHECKBOX = "checkbox"
    CHECKBOXES = "checkboxes"
    EMAIL = "email"
    FILE = "file"
    FILES = "files"
    NUMBER = "number"
    RADIO = "radio"
    SELECT = "select"
    TEXT = "text"
    TEXTAREA = "textarea"
    URL = "url"


def flash_error_data(
    form_cls: type[Form], errors: list[pydantic_core.ErrorDetails], form_data: dict[str, Any]
) -> dict[str, Any]:
    flash_data = {}
    error_field_names = set()

    for i, error in enumerate(errors):
        loc = error["loc"]
        kind = error["type"]
        msg = error["msg"]
        msg = msg.replace(": An email address", " because an email address")
        msg = msg.replace("Value error, ", "")
        original = error["input"]
        field_name, field_label = name_and_label(form_cls, i, loc)
        flash_data[field_name] = {
            "label": field_label,
            "original": json_suitable(original),
            "kind": kind,
            "msg": msg,
        }
        error_field_names.add(field_name)

    for field_name, field_value in form_data.items():
        if (field_name not in error_field_names) and (field_name != "csrf_token"):
            flash_data[f"!{field_name}"] = {
                "original": json_suitable(field_value),
            }
    return flash_data


def json_suitable(field_value: Any) -> Any:
    if isinstance(field_value, datastructures.FileStorage):
        return field_value.filename
    elif isinstance(field_value, list):
        if all(isinstance(f, datastructures.FileStorage) for f in field_value):
            return [f.filename for f in field_value]
        else:
            return field_value
    return field_value


def label(description: str, *, default: Any = ..., widget: Widget | None = None) -> Any:
    extra: dict[str, Any] = {"widget": widget.value} if widget else {}
    return pydantic.Field(default, description=description, json_schema_extra=extra)


def name_and_label(form_cls: type[Form], i: int, loc: tuple[str | int, ...]) -> tuple[str, str]:
    if loc:
        field_name = loc[0]
        if isinstance(field_name, str):
            field_info = form_cls.model_fields.get(field_name)
            if field_info and field_info.description:
                field_label = field_info.description
            else:
                field_label = field_name.replace("_", " ").title()
            return field_name, field_label
    field_name = f".{i}"
    field_label = "?"
    return field_name, field_label


async def quart_request() -> dict[str, Any]:
    form_data = await quart.request.form
    files_data = await quart.request.files

    combined_data = {}
    for key in form_data.keys():
        # This is a compromise
        # Some things expect single values, and some expect lists
        values = form_data.getlist(key)
        if len(values) == 1:
            combined_data[key] = values[0]
        else:
            combined_data[key] = values

    files_by_name: dict[str, list[datastructures.FileStorage]] = {}
    for key in files_data.keys():
        file_list = files_data.getlist(key)
        # When no files are uploaded, the browser may supply a file with an empty filename
        # We filter that out here
        non_empty_files = [f for f in file_list if f.filename]
        if non_empty_files:
            files_by_name[key] = non_empty_files

    for key, file_list in files_by_name.items():
        if key in combined_data:
            raise ValueError(f"Files key {key} already exists in form data")
        combined_data[key] = file_list

    return combined_data


async def render_columns(
    model_cls: type[Form],
    action: str | None = None,
    form_classes: str = ".atr-canary",
    submit_classes: str = "btn-primary",
    submit_label: str = "Submit",
    defaults: dict[str, Any] | None = None,
    errors: dict[str, list[str]] | None = None,
    use_error_data: bool = True,
) -> htm.Element:
    if action is None:
        action = quart.request.path

    flash_error_data: dict[str, Any] = {}
    if use_error_data:
        flashed_error_messages = quart.get_flashed_messages(category_filter=["form-error-data"])
        if flashed_error_messages:
            try:
                first_message = flashed_error_messages[0]
                if isinstance(first_message, str):
                    flash_error_data = json.loads(first_message)
            except (json.JSONDecodeError, IndexError):
                pass

    field_rows: list[htm.Element] = []
    hidden_fields: list[htm.Element | htm.VoidElement | markupsafe.Markup] = []

    csrf_token = utils.generate_csrf()
    hidden_fields.append(htpy.input(type="hidden", name="csrf_token", value=csrf_token))

    for field_name, field_info in model_cls.model_fields.items():
        if field_name == "csrf_token":
            continue

        hidden_field, row = _render_row(field_info, field_name, flash_error_data, defaults, errors)
        if hidden_field:
            hidden_fields.append(hidden_field)
        if row:
            field_rows.append(row)

    form_children: list[htm.Element | htm.VoidElement | markupsafe.Markup] = hidden_fields + field_rows

    submit_button = htpy.button(type="submit", class_=f"btn {submit_classes}")[submit_label]
    submit_div = htm.div(".col-sm-9.offset-sm-3")
    submit_row = htm.div(".row")[submit_div[submit_button]]
    form_children.append(submit_row)

    return htm.form(form_classes, action=action, method="post", enctype="multipart/form-data")[form_children]


def session(info: pydantic.ValidationInfo) -> web.Committer | None:
    ctx: dict[str, Any] = info.context or {}
    return ctx.get("session")


def to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v == "on":
        return True
    raise ValueError(f"Cannot convert {v!r} to boolean")


def to_enum_set[EnumType: enum.Enum](v: Any, enum_class: type[EnumType]) -> set[EnumType]:
    members: dict[str, EnumType] = {member.value: member for member in enum_class}
    if isinstance(v, set):
        return {item for item in v if isinstance(item, enum_class)}
    if isinstance(v, list):
        return {members[item] for item in v if item in members}
    if isinstance(v, str):
        if v in members:
            return {members[v]}
        raise ValueError(f"Invalid enum value: {v!r}")
    raise ValueError(f"Expected a set of enum values, got {type(v).__name__}")


def to_filestorage(v: Any) -> datastructures.FileStorage:
    if not isinstance(v, datastructures.FileStorage):
        raise ValueError("Expected an uploaded file")
    return v


def to_filestorage_list(v: Any) -> list[datastructures.FileStorage]:
    if isinstance(v, list):
        result = []
        for item in v:
            if not isinstance(item, datastructures.FileStorage):
                raise ValueError("Expected a list of uploaded files")
            result.append(item)
        return result
    if isinstance(v, datastructures.FileStorage):
        return [v]
    raise ValueError("Expected a list of uploaded files")


def to_int(v: Any) -> int:
    # if v == "":
    #     return 0
    try:
        return int(v)
    except ValueError:
        raise ValueError(f"Invalid integer value: {v!r}")


# Validator types come before other functions
# We must not use the "type" keyword here, otherwise Pydantic complains

Bool = Annotated[
    bool,
    functional_validators.BeforeValidator(to_bool),
    pydantic.Field(default=False),
]

Email = pydantic.EmailStr

File = Annotated[
    datastructures.FileStorage,
    functional_validators.BeforeValidator(to_filestorage),
]

FileList = Annotated[
    list[datastructures.FileStorage],
    functional_validators.BeforeValidator(to_filestorage_list),
    pydantic.Field(default_factory=list),
]

Int = Annotated[
    int,
    functional_validators.BeforeValidator(to_int),
]


class Set[EnumType: enum.Enum]:
    def __iter__(self) -> Iterator[EnumType]:
        # For type checkers
        raise NotImplementedError

    @staticmethod
    def __class_getitem__(enum_class: type[EnumType]):
        def validator(v: Any) -> set[EnumType]:
            return to_enum_set(v, enum_class)

        return Annotated[
            set[enum_class],
            functional_validators.BeforeValidator(validator),
            pydantic.Field(default_factory=set),
        ]


def validate(model_cls: Any, form: dict[str, Any], context: dict[str, Any] | None = None) -> pydantic.BaseModel:
    # Since pydantic.TypeAdapter accepts Any, we do the same
    return pydantic.TypeAdapter(model_cls).validate_python(form, context=context)


def value(type_alias: Any) -> Any:
    # This is for unwrapping from Literal for discriminators
    if hasattr(type_alias, "__value__"):
        type_alias = type_alias.__value__
    args = get_args(type_alias)
    if args:
        return args[0]
    raise ValueError(f"Cannot extract default value from {type_alias}")


def widget(widget_type: Widget) -> Any:
    return pydantic.Field(..., json_schema_extra={"widget": widget_type.value})


def _render_widget(  # noqa: C901
    field_name: str,
    field_info: pydantic.fields.FieldInfo,
    field_value: Any,
    field_errors: list[str] | None,
    is_required: bool,
) -> htm.Element | htm.VoidElement:
    widget_type = _get_widget_type(field_info)
    widget_classes = _get_widget_classes(widget_type, field_errors)

    base_attrs: dict[str, str] = {"name": field_name, "id": field_name, "class_": widget_classes}

    elements: list[htm.Element | htm.VoidElement] = []

    match widget_type:
        case Widget.CHECKBOX:
            attrs: dict[str, str] = {
                "type": "checkbox",
                "name": field_name,
                "id": field_name,
                "class_": "form-check-input",
            }
            if field_value:
                attrs["checked"] = ""
            widget = htpy.input(**attrs)

        case Widget.CHECKBOXES:
            choices = _get_choices(field_info)
            if isinstance(field_value, set):
                selected_values = [item.value for item in field_value]
            else:
                selected_values = field_value if isinstance(field_value, list) else []
            checkboxes = []
            for val, label in choices:
                checkbox_id = f"{field_name}_{val}"
                checkbox_attrs: dict[str, str] = {
                    "type": "checkbox",
                    "name": field_name,
                    "id": checkbox_id,
                    "value": val,
                    "class_": "form-check-input",
                }
                if val in selected_values:
                    checkbox_attrs["checked"] = ""
                checkbox_input = htpy.input(**checkbox_attrs)
                checkbox_label = htpy.label(for_=checkbox_id, class_="form-check-label")[label]
                checkboxes.append(htpy.div(class_="form-check")[checkbox_input, checkbox_label])
            elements.extend(checkboxes)
            widget = htm.div[checkboxes]

        case Widget.EMAIL:
            attrs = {**base_attrs, "type": "email"}
            if field_value:
                attrs["value"] = str(field_value)
            widget = htpy.input(**attrs)

        case Widget.FILE:
            widget = htpy.input(type="file", **base_attrs)

        case Widget.FILES:
            attrs = {**base_attrs, "multiple": ""}
            widget = htpy.input(type="file", **attrs)

        case Widget.NUMBER:
            attrs = {**base_attrs, "type": "number"}
            attrs["value"] = "0" if (field_value is None) else str(field_value)
            widget = htpy.input(**attrs)

        case Widget.RADIO:
            choices = _get_choices(field_info)
            radios = []
            for val, label in choices:
                radio_id = f"{field_name}_{val}"
                radio_attrs: dict[str, str] = {
                    "type": "radio",
                    "name": field_name,
                    "id": radio_id,
                    "value": val,
                    "class_": "form-check-input",
                }
                if is_required:
                    radio_attrs["required"] = ""
                if val == field_value:
                    radio_attrs["checked"] = ""
                radio_input = htpy.input(**radio_attrs)
                radio_label = htpy.label(for_=radio_id, class_="form-check-label")[label]
                radios.append(htpy.div(class_="form-check")[radio_input, radio_label])
            elements.extend(radios)
            widget = htm.div[radios]

        case Widget.SELECT:
            choices = _get_choices(field_info)
            options = [
                htpy.option(
                    value=val,
                    selected="" if (val == field_value) else None,
                )[label]
                for val, label in choices
            ]
            widget = htpy.select(**base_attrs)[options]

        case Widget.TEXT:
            attrs = {**base_attrs, "type": "text"}
            if field_value:
                attrs["value"] = str(field_value)
            widget = htpy.input(**attrs)

        case Widget.TEXTAREA:
            widget = htpy.textarea(**base_attrs)[field_value or ""]

        case Widget.URL:
            attrs = {**base_attrs, "type": "url"}
            if field_value:
                attrs["value"] = str(field_value)
            widget = htpy.input(**attrs)

    if not elements:
        elements.append(widget)

    if field_errors:
        error_text = " ".join(field_errors)
        error_div = htm.div(".invalid-feedback.d-block")[error_text]
        elements.append(error_div)

    return htm.div[elements] if len(elements) > 1 else elements[0]


def _get_choices(field_info: pydantic.fields.FieldInfo) -> list[tuple[str, str]]:
    annotation = field_info.annotation
    origin = get_origin(annotation)

    if origin is Literal:
        return [(v, v) for v in get_args(annotation)]

    if origin is set:
        args = get_args(annotation)
        if args and hasattr(args[0], "__members__"):
            enum_class = args[0]
            return [(member.value, member.value) for member in enum_class]

    if origin is list:
        args = get_args(annotation)
        if args and get_origin(args[0]) is Literal:
            return [(v, v) for v in get_args(args[0])]

    return []


def _get_widget_classes(widget_type: Widget, has_errors: list[str] | None) -> str:
    match widget_type:
        case Widget.SELECT:
            base_class = "form-select"
        case Widget.CHECKBOX | Widget.RADIO | Widget.CHECKBOXES:
            return "form-check-input"
        case _:
            base_class = "form-control"

    if has_errors:
        return f"{base_class} is-invalid"
    return base_class


def _get_widget_type(field_info: pydantic.fields.FieldInfo) -> Widget:  # noqa: C901
    json_schema_extra = field_info.json_schema_extra or {}
    if isinstance(json_schema_extra, dict) and "widget" in json_schema_extra:
        widget_value = json_schema_extra["widget"]
        if isinstance(widget_value, str):
            try:
                return Widget(widget_value)
            except ValueError:
                pass

    annotation = field_info.annotation
    origin = get_origin(annotation)

    if (annotation is not None) and hasattr(annotation, "__value__"):
        annotation = annotation.__value__
        origin = get_origin(annotation)

    if isinstance(annotation, types.UnionType) or (origin is type(None)):
        args = get_args(annotation)
        non_none_types = [arg for arg in args if (arg is not type(None))]
        if non_none_types:
            annotation = non_none_types[0]
            origin = get_origin(annotation)

    if origin is Annotated:
        args = get_args(annotation)
        annotation = args[0]
        origin = get_origin(annotation)

    if annotation is datastructures.FileStorage:
        return Widget.FILE

    if annotation is bool:
        return Widget.CHECKBOX

    if annotation is pydantic.EmailStr:
        return Widget.EMAIL

    if annotation in (int, float):
        return Widget.NUMBER

    if origin is Literal:
        return Widget.SELECT

    if origin is set:
        args = get_args(annotation)
        if args and hasattr(args[0], "__members__"):
            return Widget.CHECKBOXES

    if origin is list:
        args = get_args(annotation)
        if args:
            first_arg = args[0]
            if get_origin(first_arg) is Literal:
                return Widget.CHECKBOXES
            if first_arg is datastructures.FileStorage:
                return Widget.FILES
            if hasattr(first_arg, "__value__"):
                inner = first_arg.__value__
                inner_origin = get_origin(inner)
                if inner_origin is Annotated:
                    inner_args = get_args(inner)
                    if inner_args and (inner_args[0] is datastructures.FileStorage):
                        return Widget.FILES

    return Widget.TEXT


def _render_field_value(
    field_name: str,
    flash_error_data: dict[str, Any],
    has_flash_error: bool,
    defaults: dict[str, Any] | None,
    field_info: pydantic.fields.FieldInfo,
) -> Any:
    has_flash_data = f"!{field_name}" in flash_error_data
    if has_flash_error:
        field_value = flash_error_data[field_name]["original"]
    elif has_flash_data:
        field_value = flash_error_data[f"!{field_name}"]["original"]
    elif defaults:
        field_value = defaults.get(field_name)
    elif not field_info.is_required():
        field_value = field_info.get_default(call_default_factory=True)
    else:
        field_value = None
    return field_value


def _render_row(
    field_info: pydantic.fields.FieldInfo,
    field_name: str,
    flash_error_data: dict[str, Any],
    defaults: dict[str, Any] | None,
    errors: dict[str, list[str]] | None,
) -> tuple[htm.VoidElement | None, htm.Element | None]:
    widget_type = _get_widget_type(field_info)
    has_flash_error = field_name in flash_error_data
    field_value = _render_field_value(field_name, flash_error_data, has_flash_error, defaults, field_info)

    compound_widget = widget_type in (Widget.CHECKBOXES, Widget.FILES)
    substantial_field_value = field_value is not None
    field_value_is_not_list = not isinstance(field_value, list)

    if compound_widget and substantial_field_value and field_value_is_not_list:
        field_value = [field_value]
    field_errors = errors.get(field_name) if errors else None

    if (field_name == DISCRIMINATOR_NAME) and (field_info.default is not None):
        default_value = field_info.default
        return htpy.input(type="hidden", name=DISCRIMINATOR_NAME, value=default_value), None

    label_text = field_info.description or field_name.replace("_", " ").title()
    is_required = field_info.is_required()

    label_classes = "col-sm-3 col-form-label text-sm-end"
    label_classes_with_error = f"{label_classes} text-danger" if has_flash_error else label_classes
    label_elem = htpy.label(for_=field_name, class_=label_classes_with_error)[label_text]

    widget_elem = _render_widget(
        field_name=field_name,
        field_info=field_info,
        field_value=field_value,
        field_errors=field_errors,
        is_required=is_required,
    )

    row_div = htm.div(".mb-3.row")
    widget_div = htm.div(".col-sm-8")

    widget_div_contents: list[htm.Element | htm.VoidElement] = [widget_elem]
    if has_flash_error:
        error_msg = flash_error_data[field_name]["msg"]
        error_div = htm.div(".text-danger.mt-1")[f"Error: {error_msg}"]
        widget_div_contents.append(error_div)

    return None, row_div[label_elem, widget_div[widget_div_contents]]
