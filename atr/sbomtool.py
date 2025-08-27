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
import datetime
import enum
import pathlib
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Any, Literal

import pydantic
import yyjson

THE_APACHE_SOFTWARE_FOUNDATION = "The Apache Software Foundation"
# TODO: Simple cache to avoid rate limiting, not thread safe
CACHE_PATH = pathlib.Path("/tmp/sbomtool-cache.json")
VERSION = "0.0.1-dev1"


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

    def __str__(self) -> str:
        return f"missing {self.property.name}"


@dataclasses.dataclass
class MissingComponentProperty:
    property: ComponentProperty
    index: int | None = None

    def __str__(self) -> str:
        if self.index is None:
            return f"missing {self.property.name} in primary component"
        return f"missing {self.property.name} in component {self.index}"


type Missing = MissingProperty | MissingComponentProperty


@dataclasses.dataclass
class Bundle:
    doc: yyjson.Document
    bom: Bom


class SBOMQSSummary(Lax):
    total_score: float


class SBOMQSReport(Lax):
    summary: SBOMQSSummary


def assemble_metadata_supplier(doc: yyjson.Document, patch: Patch) -> None:
    assemble_metadata(doc, patch)
    # NOTE: The sbomqs tool requires a URL (or email) on a supplier
    patch.append(
        AddOp(
            op="add",
            path="/metadata/supplier",
            value={
                "name": THE_APACHE_SOFTWARE_FOUNDATION,
                "url": ["https://apache.org/"],
            },
        )
    )


def assemble_metadata(doc: yyjson.Document, patch: Patch) -> None:
    if get_pointer(doc, "/metadata") is None:
        patch.append(
            AddOp(
                op="add",
                path="/metadata",
                value={},
            )
        )


def assemble_metadata_component(doc: yyjson.Document, patch: Patch) -> None:
    # This is a hard failure
    # The SBOM is completely invalid, and there is no recovery
    raise ValueError("metadata.component is required")


def assemble_metadata_author(doc: yyjson.Document, patch: Patch) -> None:
    assemble_metadata(doc, patch)
    if get_pointer(doc, "/metadata/author") is None:
        patch.append(
            AddOp(
                op="add",
                path="/metadata/author",
                value=f"sbomtool v{VERSION}, by ASF Tooling",
            )
        )


def assemble_metadata_timestamp(doc: yyjson.Document, patch: Patch) -> None:
    assemble_metadata(doc, patch)
    if get_pointer(doc, "/metadata/timestamp") is None:
        patch.append(
            AddOp(
                op="add",
                path="/metadata/timestamp",
                value=datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        )


def assemble_dependencies(doc: yyjson.Document, patch: Patch) -> None:
    # This is just a warning
    # There is nothing we can do, but we should alert the user
    pass


def assemble_component_supplier(doc: yyjson.Document, patch: Patch, index: int) -> None:
    # We need to detect whether this is an ASF component
    # If it is, we can trivially fix it
    # If not, this is much more difficult
    # NOTE: The sbomqs tool requires a URL (or email) on a supplier
    def make_supplier_op(name: str, url: str) -> AddOp:
        nonlocal index
        return AddOp(
            op="add",
            path=f"/components/{index}/supplier",
            value={
                "name": name,
                "url": [url],
            },
        )

    add_asf_op = make_supplier_op(
        THE_APACHE_SOFTWARE_FOUNDATION,
        "https://apache.org/",
    )

    if get_pointer(doc, f"/components/{index}/publisher") == THE_APACHE_SOFTWARE_FOUNDATION:
        patch.append(add_asf_op)
        return

    if purl := get_pointer(doc, f"/components/{index}/purl"):
        if purl.startswith("pkg:maven/org.apache."):
            patch.append(add_asf_op)
            return

    if group_id := get_pointer(doc, f"/components/{index}/group"):
        if group_id.startswith("org.apache."):
            patch.append(add_asf_op)
            return
        elif group_id.startswith("com.github."):
            github_user = group_id.split(".", 2)[2]
            add_github_op = make_supplier_op(
                f"@github/{github_user}",
                f"https://github.com/{github_user}",
            )
            patch.append(add_github_op)
            return

    if bom_ref := get_pointer(doc, f"/components/{index}/bom-ref"):
        if bom_ref.startswith("pkg:maven/org.apache."):
            patch.append(add_asf_op)
            return

    if purl and purl.startswith("pkg:maven/"):
        package_version = purl.removeprefix("pkg:maven/").rsplit("?", 1)[0]
        package, version = package_version.rsplit("@", 1)
        package = package.replace("/", ":")
        key = f"{package} / {version}"

        def supplier_op_from_url(url: str) -> AddOp:
            if url.startswith("https://github.com/"):
                github_user = url.removeprefix("https://github.com/").split("/", 1)[0]
                return make_supplier_op(f"@github/{github_user}", f"https://github.com/{github_user}")
            return make_supplier_op(url, url)

        cache: dict[str, Any] = maven_cache_read()

        if key in cache:
            cached = cache[key]
            if cached is None:
                return
            if isinstance(cached, str) and cached:
                patch.append(supplier_op_from_url(cached))
            return

        url = f"https://api.deps.dev/v3/systems/MAVEN/packages/{package}/versions/{version}"
        try:
            with urllib.request.urlopen(url) as response:
                data = yyjson.Document(response.read())
        except urllib.error.HTTPError:
            cache[key] = None
            maven_cache_write(cache)
            return
        links = get_pointer(data, "/links") or []
        homepage = None
        for i, link in enumerate(links):
            if isinstance(link, dict) and link.get("label") == "HOMEPAGE":
                homepage = link.get("url")
                break
        if homepage:
            patch.append(supplier_op_from_url(homepage))
            cache[key] = homepage
        else:
            cache[key] = None
        maven_cache_write(cache)
        return


def assemble_component_name(doc: yyjson.Document, patch: Patch, index: int) -> None:
    # May be able to derive this from other fields
    pass


def assemble_component_version(doc: yyjson.Document, patch: Patch, index: int) -> None:
    # May be able to derive this from other fields
    pass


def assemble_component_identifier(doc: yyjson.Document, patch: Patch, index: int) -> None:
    # May be able to derive this from other fields
    pass


def bundle_to_patch(bundle: Bundle) -> Patch:
    _warnings, errors = ntia_2021_conformance_issues(bundle.bom)
    patch_ops = ntia_2021_conformance_patch(bundle.doc, errors)
    return patch_ops


def get_pointer(doc: yyjson.Document, path: str) -> Any | None:
    try:
        return doc.get_pointer(path)
    except ValueError as e:
        # TODO: This is not necessarily stable
        if str(e) == "JSON pointer cannot be resolved":
            return None
        raise


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
        case "scores":
            if patch_ops:
                patch_data = patch_to_data(patch_ops)
                merged = bundle.doc.patch(yyjson.Document(patch_data))
                print(sbomqs_total_score(bundle.doc), "->", sbomqs_total_score(merged))
            else:
                print(sbomqs_total_score(bundle.doc))
        case "validate":
            print(bundle.doc.dumps())
        case "missing":
            _warnings, errors = ntia_2021_conformance_issues(bundle.bom)
            for error in errors:
                print(error)
            # for warning in warnings:
            #     print(warning)
        case "where":
            _warnings, errors = ntia_2021_conformance_issues(bundle.bom)
            for error in errors:
                match error:
                    case MissingProperty():
                        print(f"metadata.{error.property.name}")
                        print()
                    case MissingComponentProperty():
                        components = bundle.bom.components
                        primary_component = bundle.bom.metadata and bundle.bom.metadata.component
                        if (error.index is not None) and (components is not None):
                            print(components[error.index].model_dump_json(indent=2))
                            print()
                        elif primary_component is not None:
                            print(primary_component.model_dump_json(indent=2))
                            print()
        case _:
            print(f"unknown command: {sys.argv[1]}")
            sys.exit(1)


def maven_cache_read() -> dict[str, Any]:
    try:
        with open(CACHE_PATH) as f:
            return yyjson.load(f)
    except Exception:
        return {}


def maven_cache_write(cache: dict[str, Any]) -> None:
    try:
        with open(CACHE_PATH, "w") as f:
            yyjson.dump(cache, f)
    except Exception:
        pass


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
    # TODO: Add tool metadata
    for error in errors:
        match error:
            case MissingProperty(property):
                match property:
                    case Property.METADATA_SUPPLIER:
                        assemble_metadata_supplier(doc, patch)
                    case Property.METADATA:
                        assemble_metadata(doc, patch)
                    case Property.METADATA_COMPONENT:
                        assemble_metadata_component(doc, patch)
                    case Property.METADATA_AUTHOR:
                        assemble_metadata_author(doc, patch)
                    case Property.METADATA_TIMESTAMP:
                        assemble_metadata_timestamp(doc, patch)
                    case Property.DEPENDENCIES:
                        assemble_dependencies(doc, patch)
            case MissingComponentProperty(property, index):
                match property:
                    case ComponentProperty.SUPPLIER if index is not None:
                        assemble_component_supplier(doc, patch, index)
                    case ComponentProperty.NAME if index is not None:
                        assemble_component_name(doc, patch, index)
                    case ComponentProperty.VERSION if index is not None:
                        assemble_component_version(doc, patch, index)
                    case ComponentProperty.IDENTIFIER if index is not None:
                        assemble_component_identifier(doc, patch, index)
    return patch


def patch_to_data(patch: Patch) -> list[dict[str, Any]]:
    return [op.model_dump(by_alias=True, exclude_none=True) for op in patch]


def path_to_bundle(path: pathlib.Path) -> Bundle:
    text = path.read_text(encoding="utf-8")
    return Bundle(doc=yyjson.Document(text), bom=Bom.model_validate_json(text))


def sbomqs_total_score(value: pathlib.Path | str | yyjson.Document) -> float:
    args = ["sbomqs", "compliance", "--ntia", "--json"]
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as tf:
        match value:
            case yyjson.Document():
                tf.write(value.dumps())
            case pathlib.Path():
                tf.write(pathlib.Path(value).read_text(encoding="utf-8"))
            case str():
                tf.write(value)
        args.append(tf.name)

        proc = subprocess.run(
            args,
            text=True,
            capture_output=True,
        )
    if proc.returncode != 0:
        err = proc.stderr.strip() or "sbomqs failed"
        raise RuntimeError(err)
    report = SBOMQSReport.model_validate_json(proc.stdout)
    return report.summary.total_score


if __name__ == "__main__":
    main()
