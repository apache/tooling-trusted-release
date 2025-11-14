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
import pathlib
import types
from typing import TYPE_CHECKING, Annotated, Any, Final, Literal, TypeAliasType, get_args, get_origin

import htpy
import markupsafe
import pydantic
import pydantic.functional_validators as functional_validators
import quart
import quart.datastructures as datastructures
import quart_wtf.utils as utils

import atr.htm as htm
import atr.models.schema as schema

if TYPE_CHECKING:
    from collections.abc import Iterator

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
    CUSTOM = "custom"
    EMAIL = "email"
    FILE = "file"
    FILES = "files"
    HIDDEN = "hidden"
    NUMBER = "number"
    RADIO = "radio"
    SELECT = "select"
    TEXT = "text"
    TEXTAREA = "textarea"
    URL = "url"


def csrf_input() -> htm.VoidElement:
    csrf_token = utils.generate_csrf()
    return htpy.input(type="hidden", name="csrf_token", value=csrf_token)


def flash_error_data(
    form_cls: type[Form] | TypeAliasType, errors: list[pydantic_core.ErrorDetails], form_data: dict[str, Any]
) -> dict[str, Any]:
    flash_data = {}
    error_field_names = set()

    # It is not valid Python syntax to use type[Form]() in a match branch
    if isinstance(form_cls, TypeAliasType):
        # # Try to get the discriminator from form data first, then from errors
        # discriminator_value = form_data.get(DISCRIMINATOR_NAME)
        # if discriminator_value is None:
        #     discriminator_value = _discriminator_from_errors(errors)
        discriminator_value = _discriminator_from_errors(errors)
        concrete_cls = _get_concrete_cls(form_cls, discriminator_value)
    else:
        concrete_cls = form_cls

    for i, error in enumerate(errors):
        loc = error["loc"]
        kind = error["type"]
        msg = error["msg"]
        msg = msg.replace(": An email address", " because an email address")
        msg = msg.replace("Value error, ", "")
        original = error["input"]
        field_name, field_label = name_and_label(concrete_cls, i, loc)
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


def flash_error_summary(errors: list[pydantic_core.ErrorDetails], flash_data: dict[str, Any]) -> markupsafe.Markup:
    div = htm.Block(htm.div, classes=".atr-initial")
    plural = len(errors) > 1
    div.text(f"Please fix the following issue{'s' if plural else ''}:")
    with div.block(htm.ul, classes=".mt-2.mb-0") as ul:
        for i, flash_datum in enumerate(flash_data.values()):
            if i > 9:
                ul.li["And more, not shown here..."]
                break
            if "msg" in flash_datum:
                label = flash_datum["label"]
                if label == "*":
                    ul.li[flash_datum["msg"]]
                else:
                    ul.li[htm.strong[label], ": ", flash_datum["msg"]]
    summary = div.collect()
    return markupsafe.Markup(summary)


def json_suitable(field_value: Any) -> Any:
    if isinstance(field_value, datastructures.FileStorage):
        return field_value.filename
    elif isinstance(field_value, list):
        if all(isinstance(f, datastructures.FileStorage) for f in field_value):
            return [f.filename for f in field_value]
        else:
            return field_value
    return field_value


def label(
    description: str, documentation: str | None = None, *, default: Any = ..., widget: Widget | None = None
) -> Any:
    extra: dict[str, Any] = {}
    if widget is not None:
        extra["widget"] = widget.value
    if documentation is not None:
        extra["documentation"] = documentation
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
    # Might be a model validation error
    field_name = f".{i}"
    field_label = "*"
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


def _discriminator_from_errors(errors: list[pydantic_core.ErrorDetails]) -> str:
    discriminator_value = None
    for error in errors:
        loc = error["loc"]
        if loc and isinstance(loc[0], str):
            discriminator_value = loc[0]
            error["loc"] = loc[1:]
    if discriminator_value is None:
        raise ValueError("Discriminator not found")
    return discriminator_value


def _get_concrete_cls(form_cls: TypeAliasType, discriminator_value: str) -> type[Form]:
    alias_value = form_cls.__value__
    while get_origin(alias_value) is Annotated:
        alias_value = get_args(alias_value)[0]
    members = get_args(alias_value)
    if not members:
        raise ValueError(f"No members found for union type: {alias_value}")
    for member in members:
        field = member.model_fields.get(DISCRIMINATOR_NAME)
        if field and (field.default == discriminator_value):
            return member
    raise ValueError(f"Discriminator value {discriminator_value} not found in union type: {alias_value}")


def _get_flash_error_data() -> dict[str, Any]:
    flashed_error_messages = quart.get_flashed_messages(category_filter=["form-error-data"])
    if flashed_error_messages:
        try:
            first_message = flashed_error_messages[0]
            if isinstance(first_message, str):
                return json.loads(first_message)
        except (json.JSONDecodeError, IndexError):
            pass
    return {}


def render(  # noqa: C901
    model_cls: type[Form],
    action: str | None = None,
    form_classes: str = ".atr-canary.py-4",
    submit_classes: str = "btn-primary",
    submit_label: str = "Submit",
    cancel_url: str | None = None,
    textarea_rows: int = 12,
    defaults: dict[str, Any] | None = None,
    errors: dict[str, list[str]] | None = None,
    use_error_data: bool = True,
    custom: dict[str, htm.Element | htm.VoidElement] | None = None,
    empty: bool = False,
    border: bool = False,
    wider_widgets: bool = False,
    skip: list[str] | None = None,
) -> htm.Element:
    if action is None:
        action = quart.request.path

    is_empty_form = isinstance(model_cls, type) and issubclass(model_cls, Empty)
    is_empty_form |= empty
    if is_empty_form:
        if form_classes == ".atr-canary.py-4":
            form_classes = ""
        use_error_data = False
    elif border and (".px-" not in form_classes):
        form_classes += ".px-5"

    flash_error_data: dict[str, Any] = _get_flash_error_data() if use_error_data else {}
    field_rows: list[htm.Element] = []
    hidden_fields: list[htm.Element | htm.VoidElement | markupsafe.Markup] = []
    hidden_fields.append(csrf_input())
    skip_fields = set(skip) if skip else set()

    for field_name, field_info in model_cls.model_fields.items():
        if field_name == "csrf_token":
            continue
        if field_name in skip_fields:
            continue

        hidden_field, row = _render_row(
            field_info,
            field_name,
            flash_error_data,
            defaults,
            errors,
            textarea_rows,
            custom,
            border,
            wider_widgets,
        )
        if hidden_field:
            hidden_fields.append(hidden_field)
        if row:
            field_rows.append(row)

    form_children: list[htm.Element | htm.VoidElement | markupsafe.Markup] = hidden_fields + field_rows

    submit_button = htpy.button(type="submit", class_=f"btn {submit_classes}")[submit_label]
    submit_div_contents: list[htm.Element | htm.VoidElement] = [submit_button]
    if cancel_url:
        cancel_link = htpy.a(href=cancel_url, class_="btn btn-link text-secondary")["Cancel"]
        submit_div_contents.append(cancel_link)

    if is_empty_form:
        form_children.extend(submit_div_contents)
    else:
        if wider_widgets:
            submit_div = htm.div(".col-sm-10.offset-sm-2")
        else:
            submit_div = htm.div(".col-sm-9.offset-sm-3")
        submit_row = htm.div(".row")[submit_div[submit_div_contents]]
        form_children.append(submit_row)

    if custom:
        unused = ", ".join(custom.keys())
        raise ValueError(f"Custom widgets provided but not used: {unused}")

    return htm.form(form_classes, action=action, method="post", enctype="multipart/form-data")[form_children]


def render_block(block: htm.Block, *args, **kwargs) -> None:
    rendered = render(*args, **kwargs)
    block.append(rendered)


def session(info: pydantic.ValidationInfo) -> web.Committer | None:
    ctx: dict[str, Any] = info.context or {}
    return ctx.get("session")


def to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v == "on":
        return True
    raise ValueError(f"Cannot convert {v!r} to boolean")


def to_enum[EnumType: enum.Enum](v: Any, enum_class: type[EnumType]) -> EnumType:
    members: dict[str, EnumType] = {member.value: member for member in enum_class}
    if isinstance(v, enum_class):
        return v
    if isinstance(v, str):
        if v in members:
            return members[v]
        raise ValueError(f"Invalid enum value: {v!r}")
    raise ValueError(f"Expected an enum value, got {type(v).__name__}")


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


def to_filestorage(v: Any) -> datastructures.FileStorage | None:
    if (v is None) or (v == ""):
        return None

    if not isinstance(v, list):
        raise ValueError("Expected a list of uploaded files")
    if not v:
        return None
    if len(v) != 1:
        raise ValueError("Expected a single uploaded file")

    fs = v[0]
    if not isinstance(fs, datastructures.FileStorage):
        raise ValueError("Expected an uploaded file")

    if not fs.filename:
        return None

    return fs


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


def to_filename(v: Any) -> pathlib.Path | None:
    if not v:
        return None

    path = pathlib.Path(str(v))

    if len(path.parts) != 1:
        raise ValueError("Expected a filename, not a path containing directories")

    if path.is_absolute():
        # This branch should be unreachable
        raise ValueError("Absolute paths are not allowed")

    if "." in path.parts:
        raise ValueError("Self directory references (.) are not allowed")

    if ".." in path.parts:
        raise ValueError("Parent directory references (..) are not allowed")

    return path


def to_int(v: Any) -> int:
    # if v == "":
    #     return 0
    try:
        return int(v)
    except ValueError:
        raise ValueError(f"Invalid integer value: {v!r}")


def to_optional_url(v: Any) -> pydantic.HttpUrl | None:
    if (v is None) or (v == ""):
        return None
    return pydantic.TypeAdapter(pydantic.HttpUrl).validate_python(v)


def to_str_list(v: Any) -> list[str]:
    # TODO: Might need to handle the empty case
    if isinstance(v, list):
        return [str(item) for item in v]
    if isinstance(v, str):
        return [v]
    raise ValueError(f"Expected a string or list of strings, got {type(v).__name__}")


# Validator types come before other functions
# We must not use the "type" keyword here, otherwise Pydantic complains

Bool = Annotated[
    bool,
    functional_validators.BeforeValidator(to_bool),
    pydantic.Field(default=False),
]

Email = pydantic.EmailStr


class Enum[EnumType: enum.Enum]:
    @staticmethod
    def __class_getitem__(enum_class: type[EnumType]):
        def validator(v: Any) -> EnumType:
            return to_enum(v, enum_class)

        # Get the first enum member as the default
        first_member = next(iter(enum_class))
        return Annotated[
            enum_class,
            functional_validators.BeforeValidator(validator),
            pydantic.Field(default=first_member),
        ]


File = Annotated[
    datastructures.FileStorage | None,
    functional_validators.BeforeValidator(to_filestorage),
    pydantic.Field(default=None),
]

FileList = Annotated[
    list[datastructures.FileStorage],
    functional_validators.BeforeValidator(to_filestorage_list),
    pydantic.Field(default_factory=list),
]

Filename = Annotated[
    pathlib.Path | None,
    functional_validators.BeforeValidator(to_filename),
    pydantic.Field(default=None),
]

Int = Annotated[
    int,
    functional_validators.BeforeValidator(to_int),
]

OptionalURL = Annotated[
    pydantic.HttpUrl | None,
    functional_validators.BeforeValidator(to_optional_url),
    pydantic.Field(default=None),
]

StrList = Annotated[
    list[str],
    functional_validators.BeforeValidator(to_str_list),
    pydantic.Field(default_factory=list),
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


URL = pydantic.HttpUrl


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


def _get_choices(field_info: pydantic.fields.FieldInfo) -> list[tuple[str, str]]:  # noqa: C901
    annotation = field_info.annotation
    origin = get_origin(annotation)

    if origin is Literal:
        return [(v, v) for v in get_args(annotation)]

    if origin is Annotated:
        # Check whether this is an Enum[T] or Set[T] annotation
        args = get_args(annotation)
        if args:
            inner_type = args[0]
            if isinstance(inner_type, type) and issubclass(inner_type, enum.Enum):
                # This is an enum type wrapped in Annotated, from Enum[T] or Set[T]
                return [(member.name, member.value.name if hasattr(member.value, 'name') else str(member.value)) for member in inner_type]

    if origin is set:
        args = get_args(annotation)
        if args:
            enum_class = args[0]
            if isinstance(enum_class, type) and issubclass(enum_class, enum.Enum):
                return [(member.name, member.value.name if hasattr(member.value, 'name') else str(member.value)) for member in enum_class]

    if origin is list:
        args = get_args(annotation)
        if args and get_origin(args[0]) is Literal:
            return [(v, v) for v in get_args(args[0])]

    # Check for plain enum types, e.g. when Pydantic unwraps form.Enum[T]
    if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
        return [(member.name, member.value.name if hasattr(member.value, 'name') else str(member.value)) for member in annotation]

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

    if annotation is pydantic.HttpUrl:
        return Widget.URL

    if annotation in (int, float):
        return Widget.NUMBER

    # Check for single enum types
    if hasattr(annotation, "__members__"):
        return Widget.SELECT

    if origin is Literal:
        return Widget.SELECT

    if origin is set:
        args = get_args(annotation)
        if args:
            first_arg = args[0]
            if isinstance(first_arg, type) and issubclass(first_arg, enum.Enum):
                return Widget.CHECKBOXES

    if origin is list:
        args = get_args(annotation)
        if args:
            first_arg = args[0]
            if get_origin(first_arg) is Literal:
                # Literal[str, ...]
                return Widget.CHECKBOXES
            if first_arg is str:
                # StrList
                return Widget.CHECKBOXES
            if first_arg is datastructures.FileStorage:
                # FileList
                return Widget.FILES
            if hasattr(first_arg, "__value__"):
                inner = first_arg.__value__
                inner_origin = get_origin(inner)
                if inner_origin is Annotated:
                    inner_args = get_args(inner)
                    if inner_args and (inner_args[0] is datastructures.FileStorage):
                        return Widget.FILES

    return Widget.TEXT


def _parse_dynamic_choices(
    field_name: str, defaults: dict[str, Any] | None, field_value: Any
) -> tuple[list[tuple[str, str]], Any]:
    """Parse dynamic choices from defaults or field value."""
    # Check defaults first for dynamic choices
    default_value = defaults.get(field_name) if defaults else None

    if isinstance(default_value, list) and default_value:
        if isinstance(default_value[0], tuple) and (len(default_value[0]) == 2):
            # List of (value, label) tuples
            choices = default_value
            selected_value = field_value if not isinstance(field_value, list) else None
            return choices, selected_value
        else:
            # List of simple values
            choices = [(val, val) for val in default_value]
            selected_value = (
                field_value if not isinstance(field_value, list) else (default_value[0] if default_value else None)
            )
            return choices, selected_value

    # Otherwise use field_value, if it's a list
    if isinstance(field_value, list) and field_value:
        if isinstance(field_value[0], tuple) and (len(field_value[0]) == 2):
            choices = field_value
            selected_value = None
            return choices, selected_value
        else:
            choices = [(val, val) for val in field_value]
            selected_value = field_value[0] if field_value else None
            return choices, selected_value

    # Otherwise there were no dynamic choices
    return [], field_value


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
    textarea_rows: int,
    custom: dict[str, htm.Element | htm.VoidElement] | None,
    border: bool,
    wider_widgets: bool,
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

    if widget_type == Widget.HIDDEN:
        attrs = {"type": "hidden", "name": field_name, "id": field_name}
        if field_value is not None:
            attrs["value"] = str(field_value)
        return htpy.input(**attrs), None

    label_text = field_info.description or field_name.replace("_", " ").title()
    is_required = field_info.is_required()

    if wider_widgets:
        label_col_class = "col-sm-2"
        widget_col_class = ".col-sm-9"
    else:
        label_col_class = "col-sm-3"
        widget_col_class = ".col-sm-8"

    label_classes = f"{label_col_class} col-form-label text-sm-end"
    label_classes_with_error = f"{label_classes} text-danger" if has_flash_error else label_classes
    label_elem = htpy.label(for_=field_name, class_=label_classes_with_error)[label_text]

    widget_elem = _render_widget(
        field_name=field_name,
        field_info=field_info,
        field_value=field_value,
        field_errors=field_errors,
        is_required=is_required,
        textarea_rows=textarea_rows,
        custom=custom,
        defaults=defaults,
    )

    row_div = htm.div(f".mb-3.pb-3.row{'.border-bottom' if border else ''}")
    widget_div = htm.div(widget_col_class)

    widget_div_contents: list[htm.Element | htm.VoidElement] = [widget_elem]
    if has_flash_error:
        error_msg = flash_error_data[field_name]["msg"]
        error_div = htm.div(".text-danger.mt-1")[f"Error: {error_msg}"]
        widget_div_contents.append(error_div)
    else:
        # Skip documentation for CUSTOM widgets
        # Therefore CUSTOM widgets must handle their own documentation
        if widget_type != Widget.CUSTOM:
            json_schema_extra = field_info.json_schema_extra or {}
            if isinstance(json_schema_extra, dict):
                documentation = json_schema_extra.get("documentation")
                if isinstance(documentation, str):
                    doc_div = htm.div(".text-muted.mt-1.form-text")[documentation]
                    widget_div_contents.append(doc_div)

    return None, row_div[label_elem, widget_div[widget_div_contents]]


def _render_widget(  # noqa: C901
    field_name: str,
    field_info: pydantic.fields.FieldInfo,
    field_value: Any,
    field_errors: list[str] | None,
    is_required: bool,
    textarea_rows: int,
    custom: dict[str, htm.Element | htm.VoidElement] | None,
    defaults: dict[str, Any] | None,
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

            if (not choices) and isinstance(field_value, list) and field_value:
                # Render list[str] as checkboxes
                if isinstance(field_value[0], tuple) and (len(field_value[0]) == 2):
                    choices = field_value
                    selected_values = []
                else:
                    choices = [(str(v), str(v)) for v in field_value]
                    selected_values = field_value
            elif isinstance(field_value, set):
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

        case Widget.CUSTOM:
            if custom and (field_name in custom):
                widget = custom.pop(field_name)
            else:
                widget = htm.div[f"Custom widget for {field_name} not provided"]

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

        case Widget.HIDDEN:
            attrs = {"type": "hidden", "name": field_name, "id": field_name}
            if field_value is not None:
                attrs["value"] = str(field_value)
            widget = htpy.input(**attrs)

        case Widget.NUMBER:
            attrs = {**base_attrs, "type": "number"}
            attrs["value"] = "0" if (field_value is None) else str(field_value)
            widget = htpy.input(**attrs)

        case Widget.RADIO:
            # Check for dynamic choices from defaults or field_value
            dynamic_choices, selected_value = _parse_dynamic_choices(field_name, defaults, field_value)
            if dynamic_choices:
                choices = dynamic_choices
            else:
                choices = _get_choices(field_info)
                selected_value = field_value

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
                if val == selected_value:
                    radio_attrs["checked"] = ""
                radio_input = htpy.input(**radio_attrs)
                radio_label = htpy.label(for_=radio_id, class_="form-check-label")[label]
                radios.append(htpy.div(class_="form-check")[radio_input, radio_label])
            elements.extend(radios)
            widget = htm.div[radios]

        case Widget.SELECT:
            # Check for dynamic choices from defaults or field_value
            dynamic_choices, selected_value = _parse_dynamic_choices(field_name, defaults, field_value)

            if dynamic_choices:
                choices = dynamic_choices
            else:
                choices = _get_choices(field_info)
                # If field_value is an enum, extract its value for comparison
                if isinstance(field_value, enum.Enum):
                    selected_value = field_value.value
                else:
                    selected_value = field_value

            options = [
                htpy.option(
                    value=val,
                    selected="" if (val == selected_value) else None,
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
            attrs = {**base_attrs, "rows": str(textarea_rows)}
            widget = htpy.textarea(**attrs)[field_value or ""]

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
