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

import datetime
from typing import Any

import yyjson

from . import constants, models


def cache_read() -> dict[str, Any]:
    try:
        with open(constants.maven.CACHE_PATH) as file:
            return yyjson.load(file)
    except Exception:
        return {}


def cache_write(cache: dict[str, Any]) -> None:
    try:
        with open(constants.maven.CACHE_PATH, "w") as file:
            yyjson.dump(cache, file)
    except Exception:
        pass


def plugin_outdated_version(bom_value: models.bom.Bom) -> models.maven.Outdated | None:
    if bom_value.metadata is None:
        return models.maven.OutdatedMissingMetadata()
    timestamp = bom_value.metadata.timestamp
    if timestamp is None:
        # This quite often isn't available
        # We could use the file mtime, but that's extremely heuristic
        # return OutdatedMissingTimestamp()
        timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    tools = []
    tools_value = bom_value.metadata.tools
    if isinstance(tools_value, list):
        tools = tools_value
    elif tools_value:
        tools = tools_value.components or []
    for tool in tools:
        names_or_descriptions = {
            "cyclonedx maven plugin",
            "cyclonedx-maven-plugin",
        }
        name_or_description = (tool.name or tool.description or "").lower()
        if name_or_description not in names_or_descriptions:
            continue
        if tool.version is None:
            return models.maven.OutdatedMissingVersion(name=name_or_description)
        available_version = plugin_outdated_version_core(timestamp, tool.version)
        if available_version is not None:
            return models.maven.OutdatedTool(
                name=name_or_description,
                used_version=tool.version,
                available_version=available_version,
            )
    return None


def plugin_outdated_version_core(isotime: str, version: str) -> str | None:
    expected_version = version_as_of(isotime)
    if expected_version is None:
        return None
    if version == expected_version:
        return None
    expected_version_comparable = version_parse(expected_version)
    version_comparable = version_parse(version)
    # If the version used is less than the version available
    if version_comparable < expected_version_comparable:
        # Then note the version available
        return expected_version
    # Otherwise, the user is using the latest version
    return None


def version_as_of(isotime: str) -> str | None:
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
    for date, version in sorted(constants.maven.PLUGIN_VERSIONS.items(), reverse=True):
        if isotime >= date:
            return version
    return None


def version_parse(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    return int(parts[0]), int(parts[1]), int(parts[2])
