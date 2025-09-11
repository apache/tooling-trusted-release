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

from typing import Any

import pydantic

from atr.models import schema


# TODO: Maybe it's easier to use quart_schema for all our forms
# We can use source=DataSource.FORM
# But do all form input types have a pydantic counterpart?
class ReleasePolicyData(schema.Lax):
    """Pydantic model for release policy form data."""

    project_name: str

    # Compose section
    source_artifact_paths: list[str] = pydantic.Field(default_factory=list)
    binary_artifact_paths: list[str] = pydantic.Field(default_factory=list)
    github_repository_name: str = ""
    github_compose_workflow_path: list[str] = pydantic.Field(default_factory=list)
    strict_checking: bool = False

    # Vote section
    mailto_addresses: list[str] = pydantic.Field(default_factory=list)
    manual_vote: bool = False
    default_min_hours_value_at_render: int = 72
    min_hours: int = 72
    pause_for_rm: bool = False
    release_checklist: str = ""
    default_start_vote_template_hash: str = ""
    start_vote_template: str = ""
    github_vote_workflow_path: list[str] = pydantic.Field(default_factory=list)

    # Finish section
    default_announce_release_template_hash: str = ""
    announce_release_template: str = ""
    github_finish_workflow_path: list[str] = pydantic.Field(default_factory=list)
    preserve_download_files: bool = False

    @pydantic.field_validator(
        "source_artifact_paths",
        "binary_artifact_paths",
        "github_compose_workflow_path",
        "github_vote_workflow_path",
        "github_finish_workflow_path",
        mode="before",
    )
    @classmethod
    def parse_artifact_paths(cls, v: Any) -> list[str]:
        if (v is None) or (v == ""):
            return []
        if isinstance(v, str):
            return [path.strip() for path in v.split("\n") if path.strip()]
        if isinstance(v, list):
            return v
        return []

    @pydantic.field_validator("mailto_addresses", mode="before")
    @classmethod
    def parse_mailto_addresses(cls, v: Any) -> list[str]:
        if (v is None) or (v == ""):
            return []
        if isinstance(v, str):
            return [v.strip()] if v.strip() else []
        if isinstance(v, list):
            return v
        return []

    @pydantic.field_validator(
        "github_repository_name",
        "release_checklist",
        "start_vote_template",
        "announce_release_template",
        mode="before",
    )
    @classmethod
    def unwrap_values(cls, v: Any) -> Any:
        if v is None:
            return ""
        return v
