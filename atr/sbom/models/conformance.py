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
from typing import Annotated, Any, Literal

import pydantic

from .base import Strict


class Property(enum.Enum):
    METADATA = enum.auto()
    METADATA_SUPPLIER = enum.auto()
    METADATA_COMPONENT = enum.auto()
    METADATA_AUTHOR = enum.auto()
    METADATA_TIMESTAMP = enum.auto()
    DEPENDENCIES = enum.auto()


class ComponentProperty(enum.Enum):
    SUPPLIER = enum.auto()
    NAME = enum.auto()
    VERSION = enum.auto()
    IDENTIFIER = enum.auto()


class MissingProperty(Strict):
    kind: Literal["missing_property"] = "missing_property"
    property: Property

    def __str__(self) -> str:
        return f"missing {self.property.name}"

    @pydantic.field_validator("property", mode="before")
    @classmethod
    def _coerce_property(cls, value: Any) -> Property:
        return value if isinstance(value, Property) else Property(value)


class MissingComponentProperty(Strict):
    kind: Literal["missing_component_property"] = "missing_component_property"
    property: ComponentProperty
    index: int | None = None

    def __str__(self) -> str:
        if self.index is None:
            return f"missing {self.property.name} in primary component"
        return f"missing {self.property.name} in component {self.index}"

    @pydantic.field_validator("property", mode="before")
    @classmethod
    def _coerce_component_property(cls, value: Any) -> ComponentProperty:
        return value if isinstance(value, ComponentProperty) else ComponentProperty(value)


type Missing = Annotated[
    MissingProperty | MissingComponentProperty,
    pydantic.Field(discriminator="kind"),
]
MissingAdapter = pydantic.TypeAdapter(Missing)
