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

import yyjson

from . import models
from .conformance import ntia_2021_issues
from .cyclonedx import validate_cli, validate_py
from .licenses import check
from .maven import plugin_outdated_version
from .sbomqs import total_score
from .utilities import bundle_to_patch, patch_to_data, path_to_bundle


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
            _warnings, errors = ntia_2021_issues(bundle.bom)
            for error in errors:
                print(error)
            # for warning in warnings:
            #     print(warning)
        case "outdated":
            outdated = plugin_outdated_version(bundle.bom)
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
                print(total_score(bundle.doc), "->", total_score(merged))
            else:
                print(total_score(bundle.doc))
        case "validate-cli":
            errors = validate_cli(bundle)
            if not errors:
                print("valid")
            else:
                for i, e in enumerate(errors):
                    print(e)
                    if i > 25:
                        print("...")
                        break
        case "validate-py":
            errors = validate_py(bundle)
            if not errors:
                print("valid")
            else:
                for i, e in enumerate(errors):
                    print(e)
                    if i > 10:
                        print("...")
                        break
        case "where":
            _warnings, errors = ntia_2021_issues(bundle.bom)
            for error in errors:
                match error:
                    case models.conformance.MissingProperty():
                        print(f"metadata.{error.property.name}")
                        print()
                    case models.conformance.MissingComponentProperty():
                        components = bundle.bom.components
                        primary_component = bundle.bom.metadata.component if bundle.bom.metadata else None
                        if (error.index is not None) and (components is not None):
                            print(components[error.index].model_dump_json(indent=2))
                            print()
                        elif primary_component is not None:
                            print(primary_component.model_dump_json(indent=2))
                            print()
        case "license":
            warnings, errors = check(bundle.bom)
            if warnings:
                print("WARNINGS (Category B):")
                for warning in warnings:
                    version_str = f" {warning.component_version}" if warning.component_version else ""
                    scope_str = f" [scope: {warning.scope}]" if warning.scope else ""
                    print(f"  - {warning.component_name}{version_str}: {warning.license_expression}{scope_str}")
                print()
            if errors:
                print("ERRORS (Category X):")
                for error in errors:
                    version_str = f" {error.component_version}" if error.component_version else ""
                    scope_str = f" [scope: {error.scope}]" if error.scope else ""
                    unknown_suffix = " (Category X due to unknown license identifiers)" if error.any_unknown else ""
                    name_str = f"{error.component_name}{version_str}"
                    license_str = f"{error.license_expression}{scope_str}{unknown_suffix}"
                    print(f"  - {name_str}: {license_str}")
                print()
            if not warnings and not errors:
                print("All licenses are approved (Category A)")
        case _:
            print(f"unknown command: {sys.argv[1]}")
            sys.exit(1)
