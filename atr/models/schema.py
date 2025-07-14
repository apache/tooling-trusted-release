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

from collections.abc import Callable
from typing import Any

import pydantic

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


def default(default_value: Any) -> Any:
    """Helper to create a Pydantic FieldInfo object with only a default value."""
    return Field(default=default_value)


def description(desc_text: str) -> Any:
    """Helper to create a Pydantic FieldInfo object with only a description."""
    return Field(description=desc_text)


def factory(cls: Callable[[], Any]) -> Any:
    """Helper to create a Pydantic FieldInfo object with only a description."""
    return Field(default_factory=cls)
