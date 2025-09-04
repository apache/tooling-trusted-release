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
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Annotated, Any, Final, Literal

import cyclonedx.exception
import cyclonedx.schema
import cyclonedx.validation.json
import pydantic
import yyjson

if TYPE_CHECKING:
    from collections.abc import Iterable

# TODO: Simple cache to avoid rate limiting, not thread safe
CACHE_PATH = pathlib.Path("/tmp/sbomtool-cache.json")
KNOWN_PURL_PREFIXES: Final[dict[str, tuple[str, str]]] = {
    "pkg:maven/com.atlassian.": ("Atlassian", "https://www.atlassian.com/"),
    "pkg:maven/concurrent/concurrent@": (
        "Dough Lea",
        "http://gee.cs.oswego.edu/dl/classes/EDU/oswego/cs/dl/util/concurrent/intro.html",
    ),
    "pkg:maven/net.shibboleth.": ("The Shibboleth Consortium", "https://www.shibboleth.net/"),
}
KNOWN_PURL_SUPPLIERS: Final[dict[tuple[str, str], tuple[str, str]]] = {
    ("pkg:maven", "jakarta-regexp"): ("The Apache Software Foundation", "https://apache.org/"),
    ("pkg:maven", "javax.servlet.jsp"): ("Sun Microsystems", "https://sun.com/"),
    ("pkg:maven", "org.opensaml"): ("The Shibboleth Consortium", "https://www.shibboleth.net/"),
    ("pkg:maven", "org.osgi"): ("OSGi Working Group, The Eclipse Foundation", "https://www.osgi.org/"),
}
# TODO: Manually updated for now
# Use GITHUB_TOKEN=... uv run python3 scripts/github_tag_dates.py CycloneDX/cyclonedx-maven-plugin
MAVEN_PLUGIN_VERSIONS: Final[dict[str, str]] = {
    "2024-11-28T21:29:12Z": "2.9.1",
    "2024-10-08T04:31:11Z": "2.9.0",
    "2024-09-25T20:08:34Z": "2.8.2",
    "2024-08-03T22:37:32Z": "2.8.1",
    "2024-03-23T12:35:22Z": "2.8.0",
    "2024-01-16T08:02:43Z": "2.7.11",
    "2023-10-30T00:44:15Z": "2.7.10",
    "2023-05-16T18:58:36Z": "2.7.9",
    "2023-04-25T19:47:56Z": "2.7.8",
    "2023-04-17T22:41:32Z": "2.7.7",
    "2023-03-30T21:58:15Z": "2.7.6",
    "2023-02-15T23:43:55Z": "2.7.5",
    "2023-01-04T20:24:45Z": "2.7.4",
    "2022-11-10T07:37:12Z": "2.7.3",
    "2022-10-10T14:23:53Z": "2.7.2",
    "2022-07-20T04:23:22Z": "2.7.1",
    "2022-05-26T13:55:36Z": "2.7.0",
    "2022-05-03T14:19:50Z": "2.6.2",
    "2022-05-03T02:39:34Z": "2.6.1",
    "2022-04-30T05:28:10Z": "2.6.0",
    "2021-09-03T02:00:01Z": "2.5.3",
    "2021-08-19T05:29:24Z": "2.5.2",
    "2021-05-17T06:09:59Z": "2.5.1",
    "2021-05-16T06:14:27Z": "2.5.0",
    "2021-04-09T04:58:23Z": "2.4.1",
    "2021-04-01T04:09:47Z": "2.4.0",
    "2021-03-05T03:12:42Z": "2.3.0",
    "2021-01-30T23:42:19Z": "2.2.0",
    "2020-11-19T04:57:18Z": "2.1.1",
    "2020-10-12T20:09:06Z": "2.1.0",
    "2020-08-11T03:36:18Z": "2.0.3",
    "2020-07-20T01:41:20Z": "2.0.2",
    "2020-07-15T16:42:24Z": "2.0.1",
    "2020-07-14T03:45:56Z": "2.0.0",
    "2020-02-07T04:38:47Z": "1.6.4",
    "2020-02-01T04:51:27Z": "1.6.3",
    "2020-01-27T23:45:33Z": "1.6.2",
    "2020-01-24T21:33:32Z": "1.6.1",
    "2020-01-08T05:33:32Z": "1.6.0",
    "2019-11-26T21:07:06Z": "1.5.1",
    "2019-11-20T05:13:32Z": "1.5.0",
    "2019-06-19T16:41:47Z": "1.4.1",
    "2019-06-08T05:04:41Z": "1.4.0",
    "2019-01-02T20:44:14Z": "1.3.1",
    "2018-12-05T01:56:08Z": "1.3.0",
    "2018-11-28T00:27:19Z": "1.2.0",
    "2018-11-09T04:28:00Z": "1.1.3",
    "2018-07-25T20:54:37Z": "1.1.2",
    "2018-07-18T02:59:25Z": "1.1.1",
    "2018-06-07T04:20:23Z": "1.1.0",
    "2018-05-24T23:24:10Z": "1.0.1",
    "2018-05-02T16:34:05Z": "1.0.0",
}
THE_APACHE_SOFTWARE_FOUNDATION: Final[str] = "The Apache Software Foundation"
VERSION: Final[str] = "0.0.1-dev1"

# We include some sections from other files to make this standalone

# # FROM atr/models/basic.py
# type JSON = pydantic.JsonValue

# _JSON_TYPE_ADAPTER: Final[pydantic.TypeAdapter[JSON]] = pydantic.TypeAdapter(JSON)


# def as_json(value: Any) -> JSON:
#     return _JSON_TYPE_ADAPTER.validate_python(value)
# # END FROM


# FROM atr/models/schema.py
class Lax(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="allow", strict=False)


class Strict(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid", strict=True, validate_assignment=True)


# END FROM


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


class ToolComponent(Lax):
    name: str | None = None
    version: str | None = None
    description: str | None = None


class Tool(Lax):
    # vendor: str | None = None
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


# Missing* is for NTIA 2021 conformance only


class MissingProperty(Strict):
    # __match_args__ = ("property",)
    # __match_args__: ClassVar[tuple[str, ...]] = cast("Any", ("property",))
    kind: Literal["missing_property"] = "missing_property"
    property: Property

    def __str__(self) -> str:
        return f"missing {self.property.name}"

    @pydantic.field_validator("property", mode="before")
    @classmethod
    def _coerce_property(cls, v: Any) -> Property:
        return v if isinstance(v, Property) else Property(v)


class MissingComponentProperty(Strict):
    # __match_args__ = ("property", "index")
    kind: Literal["missing_component_property"] = "missing_component_property"
    property: ComponentProperty
    index: int | None = None

    def __str__(self) -> str:
        if self.index is None:
            return f"missing {self.property.name} in primary component"
        return f"missing {self.property.name} in component {self.index}"

    @pydantic.field_validator("property", mode="before")
    @classmethod
    def _coerce_component_property(cls, v: Any) -> ComponentProperty:
        return v if isinstance(v, ComponentProperty) else ComponentProperty(v)


Missing = Annotated[MissingProperty | MissingComponentProperty, pydantic.Field(discriminator="kind")]
MissingAdapter = pydantic.TypeAdapter(Missing)


# Outdated* is for any outdated tool


class OutdatedTool(Strict):
    kind: Literal["tool"] = "tool"
    name: str
    used_version: str
    available_version: str


class OutdatedMissingMetadata(Strict):
    kind: Literal["missing_metadata"] = "missing_metadata"


class OutdatedMissingTimestamp(Strict):
    kind: Literal["missing_timestamp"] = "missing_timestamp"


class OutdatedMissingVersion(Strict):
    kind: Literal["missing_version"] = "missing_version"
    name: str


Outdated = Annotated[
    OutdatedTool | OutdatedMissingMetadata | OutdatedMissingTimestamp | OutdatedMissingVersion,
    pydantic.Field(discriminator="kind"),
]
OutdatedAdapter = pydantic.TypeAdapter(Outdated)


@dataclasses.dataclass
class Bundle:
    doc: yyjson.Document
    bom: Bom
    path: pathlib.Path
    text: str


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
    tools = get_pointer(doc, "/metadata/tools")
    tool = {"name": "sbomtool", "version": VERSION, "description": "By ASF Tooling"}
    if tools is None:
        patch.append(
            AddOp(
                op="add",
                path="/metadata/tools",
                value=[tool],
            )
        )
    elif isinstance(tools, list):
        patch.append(
            AddOp(
                op="add",
                path="/metadata/tools/-",
                value=tool,
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
        prefix = tuple(purl.split("/", 2)[:2])
        if prefix in KNOWN_PURL_SUPPLIERS:
            supplier, url = KNOWN_PURL_SUPPLIERS[prefix]
            patch.append(make_supplier_op(supplier, url))
            return
        for prefix, (supplier, url) in KNOWN_PURL_PREFIXES.items():
            if purl.startswith(prefix):
                patch.append(make_supplier_op(supplier, url))
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
            domain = urllib.parse.urlparse(url).netloc
            if domain.endswith(".github.io"):
                github_user = domain.removesuffix(".github.io")
                return make_supplier_op(f"@github/{github_user}", f"https://github.com/{github_user}")
            if ("//" in url) and (url.count("/") == 2):
                url += "/"
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
    match sys.argv[1]:
        case "merge":
            patch_ops = bundle_to_patch(bundle)
            if patch_ops:
                patch_data = patch_to_data(patch_ops)
                merged = bundle.doc.patch(yyjson.Document(patch_data))
                print(merged.dumps())
            else:
                print(bundle.doc.dumps())
        case "missing":
            _warnings, errors = ntia_2021_conformance_issues(bundle.bom)
            for error in errors:
                print(error)
            # for warning in warnings:
            #     print(warning)
        case "outdated":
            outdated = maven_plugin_outdated_version(bundle.bom)
            if outdated:
                print(outdated)
            else:
                print("no outdated tool found")
        case "patch":
            patch_ops = bundle_to_patch(bundle)
            if patch_ops:
                patch_data = patch_to_data(patch_ops)
                print(yyjson.Document(patch_data).dumps())
            else:
                print("no patch needed")
        case "scores":
            patch_ops = bundle_to_patch(bundle)
            if patch_ops:
                patch_data = patch_to_data(patch_ops)
                merged = bundle.doc.patch(yyjson.Document(patch_data))
                print(sbomqs_total_score(bundle.doc), "->", sbomqs_total_score(merged))
            else:
                print(sbomqs_total_score(bundle.doc))
        case "validate-cli":
            errors = validate_cyclonedx_cli(bundle)
            if not errors:
                print("valid")
            else:
                for i, e in enumerate(errors):
                    print(e)
                    if i > 25:
                        print("...")
                        break
        case "validate-py":
            errors = validate_cyclonedx_py(bundle)
            if not errors:
                print("valid")
            else:
                for i, e in enumerate(errors):
                    print(e)
                    if i > 10:
                        print("...")
                        break
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


def maven_plugin_outdated_version(bom: Bom) -> Outdated | None:
    # Need to search for the CycloneDX Maven Plugin
    # metadata.tools.components[].name == "cyclonedx-maven-plugin"
    # We check the version against when the SBOM was generated
    # This is just a warning, of course
    if bom.metadata is None:
        return OutdatedMissingMetadata()
    timestamp = bom.metadata.timestamp
    if timestamp is None:
        # This quite often isn't available
        # We could use the file mtime, but that's extremely heuristic
        # return OutdatedMissingTimestamp()
        timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    tools = []
    t = bom.metadata.tools
    if isinstance(t, list):
        tools = t
    elif t:
        tools = t.components or []
    for tool in tools:
        names_or_descriptions = {
            "cyclonedx maven plugin",
            "cyclonedx-maven-plugin",
        }
        name_or_description = (tool.name or tool.description or "").lower()
        if name_or_description not in names_or_descriptions:
            continue
        if tool.version is None:
            return OutdatedMissingVersion(name=name_or_description)
        available_version = maven_plugin_outdated_version_core(timestamp, tool.version)
        if available_version is not None:
            return OutdatedTool(
                name=name_or_description,
                used_version=tool.version,
                available_version=available_version,
            )
    return None


def maven_plugin_outdated_version_core(isotime: str, version: str) -> str | None:
    expected_version = maven_version_as_of(isotime)
    if expected_version is None:
        return None
    if version == expected_version:
        return None
    expected_version_comparable = maven_version_parse(expected_version)
    version_comparable = maven_version_parse(version)
    # If the version used is less than the version available
    if version_comparable < expected_version_comparable:
        # Then note the version available
        return expected_version
    # Otherwise, the user is using the latest version
    return None


def maven_version_as_of(isotime: str) -> str | None:
    # Given these mappings:
    # {
    #     t3: v3
    #     t2: v2
    #     t1: v1
    # }
    # If the input is after t3, then the output is v3
    # If the input is between t2 and t1, then the output is v2
    # If the input is between t1 and t2, then the output is v1
    # If the input is before t1, then the output is None
    for date, version in sorted(MAVEN_PLUGIN_VERSIONS.items(), reverse=True):
        if isotime >= date:
            return version
    return None


def maven_version_parse(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    return int(parts[0]), int(parts[1]), int(parts[2])


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
    # This is clear from the CISA 2025 draft adding this requirement

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
            errors.append(MissingProperty(property=Property.METADATA_COMPONENT))

        # 6. Author of SBOM Data (Secondary)
        if bom.metadata.author is None:
            errors.append(MissingProperty(property=Property.METADATA_AUTHOR))

        # 7. Timestamp (Secondary)
        if bom.metadata.timestamp is None:
            errors.append(MissingProperty(property=Property.METADATA_TIMESTAMP))
    else:
        errors.append(MissingProperty(property=Property.METADATA))

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
        warnings.append(MissingProperty(property=Property.DEPENDENCIES))

    return warnings, errors


def ntia_2021_conformance_patch(doc: yyjson.Document, errors: list[Missing]) -> Patch:
    patch: Patch = []
    # TODO: Add tool metadata
    for error in errors:
        match error:
            case MissingProperty(property=property):
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
            case MissingComponentProperty(property=property, index=index):
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
    return Bundle(doc=yyjson.Document(text), bom=Bom.model_validate_json(text), path=path, text=text)


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


def validate_cyclonedx_cli(bundle: Bundle) -> list[str] | None:
    args = [
        "cyclonedx",
        "validate",
        "--fail-on-errors",
        "--input-format",
        "json",
        "--input-file",
        bundle.path.as_posix(),
    ]
    proc = subprocess.run(
        args,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        err = proc.stdout.strip() or proc.stderr.strip() or "cyclonedx failed"
        return err.splitlines()
    return None


def validate_cyclonedx_py(bundle: Bundle) -> Iterable[cyclonedx.validation.json.JsonValidationError] | None:
    json_sv = get_pointer(bundle.doc, "/specVersion")
    sv = cyclonedx.schema.SchemaVersion.V1_6
    if isinstance(json_sv, str):
        sv = cyclonedx.schema.SchemaVersion.from_version(json_sv)
    try:
        validator = cyclonedx.validation.json.JsonStrictValidator(sv)
        errors = validator.validate_str(bundle.text, all_errors=True)
    except cyclonedx.exception.MissingOptionalDependencyException:
        # Placeholder, just in case we want to handle this somehow
        raise
    if isinstance(errors, cyclonedx.validation.json.JsonValidationError):
        # The VSC type checker doesn't think this can happen
        # But pyright does
        return [errors]
    return errors


if __name__ == "__main__":
    main()
