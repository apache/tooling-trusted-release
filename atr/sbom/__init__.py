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

from typing import Final

from . import constants, models
from .conformance import ntia_2021_conformance_issues, ntia_2021_conformance_patch
from .cyclonedx import validate_cyclonedx_cli, validate_cyclonedx_py
from .licenses import check_licenses
from .maven import maven_plugin_outdated_version
from .sbomqs import sbomqs_total_score
from .spdx import spdx_license_expression_atoms
from .utilities import bundle_to_patch, patch_to_data, path_to_bundle

VERSION: Final[str] = constants.version.VERSION

Bom = models.bom.Bom
Bundle = models.bundle.Bundle
Component = models.bom.Component
LicenseCategory = models.licenses.LicenseCategory
LicenseIssue = models.licenses.LicenseIssue
Metadata = models.bom.Metadata
Missing = models.conformance.Missing
MissingAdapter = models.conformance.MissingAdapter
MissingComponentProperty = models.conformance.MissingComponentProperty
MissingProperty = models.conformance.MissingProperty
Outdated = models.maven.Outdated
OutdatedAdapter = models.maven.OutdatedAdapter
OutdatedTool = models.maven.OutdatedTool
Supplier = models.bom.Supplier

__all__ = [
    "VERSION",
    "Bom",
    "Bundle",
    "Component",
    "LicenseCategory",
    "LicenseIssue",
    "Metadata",
    "Missing",
    "MissingAdapter",
    "MissingComponentProperty",
    "MissingProperty",
    "Outdated",
    "OutdatedAdapter",
    "OutdatedTool",
    "Supplier",
    "bundle_to_patch",
    "check_licenses",
    "maven_plugin_outdated_version",
    "ntia_2021_conformance_issues",
    "ntia_2021_conformance_patch",
    "patch_to_data",
    "path_to_bundle",
    "sbomqs_total_score",
    "spdx_license_expression_atoms",
    "validate_cyclonedx_cli",
    "validate_cyclonedx_py",
]
