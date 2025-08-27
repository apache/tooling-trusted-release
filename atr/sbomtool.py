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

import dataclasses
import enum
import pathlib
import sys
from typing import Any, Literal

import pydantic
import yyjson


class Lax(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="allow", strict=False)


class Strict(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid", strict=True, validate_assignment=True)


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
    author: str | None = None
    timestamp: str | None = None
    supplier: Supplier | None = None
    component: Component | None = None


class Dependency(Lax):
    ref: str
    depends_on: list[str] | None = pydantic.Field(default=None, alias="dependsOn")


class Bom(Lax):
    metadata: Metadata | None = None
    components: list[Component] | None = None
    dependencies: list[Dependency] | None = None


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


@dataclasses.dataclass
class MissingProperty:
    property: Property


@dataclasses.dataclass
class MissingComponentProperty:
    property: ComponentProperty
    index: int | None = None


type Missing = MissingProperty | MissingComponentProperty


@dataclasses.dataclass
class Bundle:
    doc: yyjson.Document
    bom: Bom


def bundle_to_patch(bundle: Bundle) -> Patch:
    _warnings, errors = ntia_2021_conformance_issues(bundle.bom)
    patch_ops = ntia_2021_conformance_patch(bundle.doc, errors)
    return patch_ops


def main() -> None:
    path = pathlib.Path(sys.argv[2])
    bundle = path_to_bundle(path)
    patch_ops = bundle_to_patch(bundle)
    match sys.argv[1]:
        case "patch":
            if patch_ops:
                patch_data = patch_to_data(patch_ops)
                print(yyjson.Document(patch_data).dumps())
            else:
                print("no patch needed")
        case "merge":
            if patch_ops:
                patch_data = patch_to_data(patch_ops)
                merged = bundle.doc.patch(yyjson.Document(patch_data))
                print(merged.dumps())
            else:
                print(bundle.doc.dumps())
        case "validate":
            print(bundle.doc.dumps())


def ntia_2021_conformance_issues(bom: Bom) -> tuple[list[Missing], list[Missing]]:
    # 1. Supplier
    # ECMA-424 1st edition says that this is the supplier of the primary component
    # Despite it being bom.metadata.supplier and not bom.metadata.component.supplier
    # bom.metadata.supplier,
    # bom.components[].supplier

    # 2. Component Name
    # NOTE: The CycloneDX guide is missing bom.metadata.component.name
    # bom.components[].name

    # 3. Component Version
    # NOTE: The CycloneDX guide is missing bom.metadata.component.version
    # bom.components[].version

    # 4. Other Unique Identifiers
    # NOTE: The CycloneDX guide is missing bom.metadata.component.cpe,purl,swid
    # bom.components[].cpe,purl,swid
    # NOTE: NTIA 2021 does not require unique identifiers
    # This is clear from NTIA 2025 draft adding this requirement

    # 5. Dependency Relationship
    # bom.dependencies[]
    # NTIA 2021 requires this, but it can only be checked out of band

    # 6. Author of SBOM Data
    # bom.metadata.author

    # 7. Timestamp
    # bom.metadata.timestamp
    # NTIA 2021 only requires that this be present
    # It does not mandate a format

    warnings: list[Missing] = []
    errors: list[Missing] = []

    if bom.metadata is not None:
        # 1. Supplier (Primary, despite appearing to be an SBOM property)
        if bom.metadata.supplier is None:
            errors.append(MissingProperty(property=Property.METADATA_SUPPLIER))

        if bom.metadata.component is not None:
            # 2. Component Name (Primary)
            if bom.metadata.component.name is None:
                errors.append(MissingComponentProperty(property=ComponentProperty.NAME))

            # 3. Component Version (Primary)
            if bom.metadata.component.version is None:
                errors.append(MissingComponentProperty(property=ComponentProperty.VERSION))

            # 4. Other Unique Identifiers (Primary)
            # NOTE: We only warn if not present
            cpe_is_none = bom.metadata.component.cpe is None
            purl_is_none = bom.metadata.component.purl is None
            swid_is_none = bom.metadata.component.swid is None
            if cpe_is_none and purl_is_none and swid_is_none:
                warnings.append(MissingComponentProperty(property=ComponentProperty.IDENTIFIER))
        else:
            errors.append(MissingProperty(Property.METADATA_COMPONENT))

        # 6. Author of SBOM Data (Secondary)
        if bom.metadata.author is None:
            errors.append(MissingProperty(Property.METADATA_AUTHOR))

        # 7. Timestamp (Secondary)
        if bom.metadata.timestamp is None:
            errors.append(MissingProperty(Property.METADATA_TIMESTAMP))
    else:
        errors.append(MissingProperty(Property.METADATA))

    for i, component in enumerate(bom.components or []):
        # 1. Supplier (Secondary)
        if component.supplier is None:
            errors.append(MissingComponentProperty(property=ComponentProperty.SUPPLIER, index=i))

        # 2. Component Name (Secondary)
        if component.name is None:
            errors.append(MissingComponentProperty(property=ComponentProperty.NAME, index=i))

        # 3. Component Version (Secondary)
        if component.version is None:
            errors.append(MissingComponentProperty(property=ComponentProperty.VERSION, index=i))

        # 4. Other Unique Identifiers (Secondary)
        # NOTE: We only warn if not present
        component_cpe_is_none = component.cpe is None
        component_purl_is_none = component.purl is None
        component_swid_is_none = component.swid is None
        if component_cpe_is_none and component_purl_is_none and component_swid_is_none:
            warnings.append(MissingComponentProperty(property=ComponentProperty.IDENTIFIER, index=i))

    # 5. Dependency Relationship (Secondary)
    if not bom.dependencies:
        warnings.append(MissingProperty(Property.DEPENDENCIES))

    return warnings, errors


def ntia_2021_conformance_patch(doc: yyjson.Document, errors: list[Missing]) -> Patch:
    patch: Patch = []
    for error in errors:
        match error:
            case MissingProperty(property):
                match property:
                    case Property.METADATA_SUPPLIER:
                        # print("error: metadata.supplier")
                        if doc.get_pointer("/metadata") is None:
                            patch.append(AddOp(op="add", path="/metadata", value={}))
                        patch.append(
                            AddOp(
                                op="add",
                                path="/metadata/supplier",
                                value={"name": "The Apache Software Foundation"},
                            )
                        )
                # print(f"error: {property.name}")
            case MissingComponentProperty(property, _index):
                # print(f"error: {property.name} at index {index}")
                ...

    return patch


def patch_to_data(patch: Patch) -> list[dict[str, Any]]:
    return [op.model_dump(by_alias=True, exclude_none=True) for op in patch]


def path_to_bundle(path: pathlib.Path) -> Bundle:
    text = path.read_text(encoding="utf-8")
    return Bundle(doc=yyjson.Document(text), bom=Bom.model_validate_json(text))


if __name__ == "__main__":
    main()
