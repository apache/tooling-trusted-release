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

import pathlib
import sys

import pydantic


class Lax(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="allow", strict=False)


class Swid(Lax):
    tag_id: str | None = pydantic.Field(default=None, alias="tagId")


class Supplier(Lax):
    name: str | None = None


class Component(Lax):
    bom_ref: str | None = pydantic.Field(default=None, alias="bom-ref")
    name: str | None = None
    version: str | None = None
    supplier: Supplier | None = None
    purl: str | None = None
    cpe: str | None = None
    swid: Swid | None = None


class Metadata(Lax):
    supplier: Supplier | None = None
    component: Component | None = None


class Dependency(Lax):
    ref: str
    depends_on: list[str] | None = pydantic.Field(default=None, alias="dependsOn")


class Bom(Lax):
    metadata: Metadata | None = None
    components: list[Component] | None = None
    dependencies: list[Dependency] | None = None


def main() -> None:
    path = pathlib.Path(sys.argv[1])
    if err := simple_validate_path(path):
        sys.stderr.write(f"error: {err}\n")
        sys.exit(1)


def simple_validate_path(path: pathlib.Path) -> None | str:
    text = path.read_text(encoding="utf-8")
    try:
        Bom.model_validate_json(text)
    except pydantic.ValidationError as e:
        return str(e)


if __name__ == "__main__":
    main()
