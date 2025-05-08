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

import dataclasses
from collections.abc import Callable, Generator, ItemsView, Mapping
from typing import Annotated, Any, TypeVar

import pydantic
import pydantic.fields as fields
import pydantic_core

VT = TypeVar("VT")


class DictRoot(pydantic.RootModel[dict[str, VT]]):
    def __iter__(self) -> Generator[tuple[str, VT]]:
        yield from self.root.items()

    def items(self) -> ItemsView[str, VT]:
        return self.root.items()

    def get(self, key: str) -> VT | None:
        return self.root.get(key)

    def __len__(self) -> int:
        return len(self.root)


# from https://github.com/pydantic/pydantic/discussions/8755#discussioncomment-8417979
@dataclasses.dataclass
class DictToList:
    key: str

    def __get_pydantic_core_schema__(
        self,
        source_type: Any,
        handler: pydantic.GetCoreSchemaHandler,
    ) -> pydantic_core.CoreSchema:
        adapter = _get_dict_to_list_inner_type_adapter(source_type, self.key)

        return pydantic_core.core_schema.no_info_before_validator_function(
            _get_dict_to_list_validator(adapter, self.key),
            handler(source_type),
        )


# For convenience
Field = pydantic.Field


class Strict(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid", strict=True, validate_assignment=True)


def alias(alias_name: str) -> Any:
    """Helper to create a Pydantic FieldInfo object with only an alias."""
    return Field(alias=alias_name)


def alias_opt(alias_name: str) -> Any:
    """Helper to create a Pydantic FieldInfo object with only an alias."""
    return Field(alias=alias_name, default=None)


def description(desc_text: str) -> Any:
    """Helper to create a Pydantic FieldInfo object with only a description."""
    return Field(description=desc_text)


def factory(cls: Callable[[], Any]) -> Any:
    """Helper to create a Pydantic FieldInfo object with only a description."""
    return Field(default_factory=cls)


def _get_dict_to_list_inner_type_adapter(source_type: Any, key: str) -> pydantic.TypeAdapter[dict[Any, Any]]:
    root_adapter = pydantic.TypeAdapter(source_type)
    schema = root_adapter.core_schema

    # support further nesting of model classes
    if schema["type"] == "definitions":
        schema = schema["schema"]

    assert schema["type"] == "list"
    assert (item_schema := schema["items_schema"])  # pyright: ignore[reportTypedDictNotRequiredAccess, reportGeneralTypeIssues]
    assert item_schema["type"] == "model"  # pyright: ignore[reportTypedDictNotRequiredAccess, reportGeneralTypeIssues, reportCallIssue, reportArgumentType]
    assert (cls := item_schema["cls"])  # pyright: ignore[reportTypedDictNotRequiredAccess, reportGeneralTypeIssues, reportCallIssue, reportArgumentType] # noqa: RUF018

    fields = cls.model_fields

    assert (key_field := fields.get(key))  # noqa: RUF018
    assert (other_fields := {k: v for k, v in fields.items() if k != key})  # noqa: RUF018

    model_name = f"{cls.__name__}Inner"

    # Create proper field definitions for create_model
    inner_model = pydantic.create_model(model_name, **{k: (v.annotation, v) for k, v in other_fields.items()})  # type: ignore
    return pydantic.TypeAdapter(dict[Annotated[str, key_field], inner_model])  # type: ignore


def _get_dict_to_list_validator(inner_adapter: pydantic.TypeAdapter[dict[Any, Any]], key: str) -> Any:
    def validator(val: Any) -> Any:
        if isinstance(val, dict):
            validated = inner_adapter.validate_python(val)

            # need to get the alias of the field in the nested model
            # as this will be fed into the actual model class
            def get_alias(field_name: str, field_infos: Mapping[str, fields.FieldInfo]) -> Any:
                field = field_infos[field_name]
                return field.alias if field.alias else field_name

            return [
                {key: k, **{get_alias(f, v.model_fields): getattr(v, f) for f in v.model_fields}}
                for k, v in validated.items()
            ]

        return val

    return validator
