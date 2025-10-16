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

import pydantic

from .base import Lax


class Swid(Lax):
    tag_id: str | None = pydantic.Field(default=None, alias="tagId")


class Supplier(Lax):
    name: str | None = None


class License(Lax):
    id: str | None = None
    name: str | None = None
    url: str | None = None


class LicenseChoice(Lax):
    license: License | None = None
    expression: str | None = None


class Component(Lax):
    bom_ref: str | None = pydantic.Field(default=None, alias="bom-ref")
    name: str | None = None
    version: str | None = None
    supplier: Supplier | None = None
    purl: str | None = None
    cpe: str | None = None
    swid: Swid | None = None
    licenses: list[LicenseChoice] | None = None
    scope: str | None = None


class ToolComponent(Lax):
    name: str | None = None
    version: str | None = None
    description: str | None = None


class Tool(Lax):
    name: str | None = None
    version: str | None = None
    description: str | None = None


class Tools(Lax):
    components: list[ToolComponent] | None = None


class Metadata(Lax):
    author: str | None = None
    timestamp: str | None = None
    supplier: Supplier | None = None
    component: Component | None = None
    tools: Tools | list[Tool] | None = None


class Dependency(Lax):
    ref: str
    depends_on: list[str] | None = pydantic.Field(default=None, alias="dependsOn")


class Bom(Lax):
    metadata: Metadata | None = None
    components: list[Component] | None = None
    dependencies: list[Dependency] | None = None
