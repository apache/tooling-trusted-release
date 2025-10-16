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

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import pathlib

import yyjson

from . import models


def bundle_to_patch(bundle_value: models.bundle.Bundle) -> models.patch.Patch:
    from .conformance import ntia_2021_issues, ntia_2021_patch

    _warnings, errors = ntia_2021_issues(bundle_value.bom)
    patch_ops = ntia_2021_patch(bundle_value.doc, errors)
    return patch_ops


def get_pointer(doc: yyjson.Document, path: str) -> Any | None:
    try:
        return doc.get_pointer(path)
    except ValueError as exc:
        # TODO: This is not necessarily stable
        if str(exc) == "JSON pointer cannot be resolved":
            return None
        raise


def patch_to_data(patch_ops: models.patch.Patch) -> list[dict[str, Any]]:
    return [op.model_dump(by_alias=True, exclude_none=True) for op in patch_ops]


def path_to_bundle(path: pathlib.Path) -> models.bundle.Bundle:
    text = path.read_text(encoding="utf-8")
    bom = models.bom.Bom.model_validate_json(text)
    return models.bundle.Bundle(doc=yyjson.Document(text), bom=bom, path=path, text=text)
