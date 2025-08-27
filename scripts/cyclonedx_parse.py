#!/usr/bin/env python3

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

import importlib.util
import pathlib
import sys

import pydantic

if not importlib.util.find_spec("atr"):
    sys.path.append(".")

import atr.models.cyclonedx as cyclonedx


def main(argv: list[str]) -> None:
    if len(argv) != 2:
        sys.stderr.write(
            "usage: uv run scripts/cyclonedx_parse.py <sbom.cdx.json>\n",
        )
        sys.exit(2)

    path = pathlib.Path(argv[1])
    try:
        data = path.read_text(encoding="utf-8")
        _ = cyclonedx.CyclonedxBillOfMaterialsStandard.model_validate_json(data)
    except (OSError, pydantic.ValidationError, ValueError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        sys.exit(1)

    print("ok")


if __name__ == "__main__":
    main(sys.argv)
