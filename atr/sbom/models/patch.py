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

from typing import Any, Literal

import pydantic

from .base import Strict


class AddOp(Strict):
    op: Literal["add"]
    path: str
    value: Any


class CopyOp(Strict):
    op: Literal["copy"]
    path: str
    from_: str = pydantic.Field(alias="from")


class MoveOp(Strict):
    op: Literal["move"]
    path: str
    from_: str = pydantic.Field(alias="from")


class RemoveOp(Strict):
    op: Literal["remove"]
    path: str


class ReplaceOp(Strict):
    op: Literal["replace"]
    path: str
    value: Any


class TestOp(Strict):
    op: Literal["test"]
    path: str
    value: Any


type PatchOp = AddOp | RemoveOp | ReplaceOp | MoveOp | CopyOp | TestOp
type Patch = list[PatchOp]
