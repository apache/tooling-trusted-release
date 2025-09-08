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

import pydantic

import atr.models.schema as schema
import atr.models.sql as sql


class ArtifactHubAvailableVersion(schema.Lax):
    ts: int


class ArtifactHubLink(schema.Lax):
    url: str | None = None
    name: str | None = None


class ArtifactHubRepository(schema.Lax):
    name: str | None = None


class ArtifactHubResponse(schema.Lax):
    available_versions: list[ArtifactHubAvailableVersion] = pydantic.Field(default_factory=list)
    home_url: str | None = None
    links: list[ArtifactHubLink] = pydantic.Field(default_factory=list)
    name: str | None = None
    version: str | None = None
    repository: ArtifactHubRepository | None = None


class DockerResponse(schema.Lax):
    tag_last_pushed: str | None = None


class GitHubResponse(schema.Lax):
    published_at: str | None = None
    html_url: str | None = None


class MavenDoc(schema.Lax):
    timestamp: int | None = None


class MavenResponseBody(schema.Lax):
    start: int | None = None
    docs: list[MavenDoc] = pydantic.Field(default_factory=list)


class MavenResponse(schema.Lax):
    response: MavenResponseBody = pydantic.Field(default_factory=MavenResponseBody)


class NpmResponse(schema.Lax):
    name: str | None = None
    time: dict[str, str] = pydantic.Field(default_factory=dict)
    homepage: str | None = None


class PyPIUrl(schema.Lax):
    upload_time_iso_8601: str | None = None
    url: str | None = None


class PyPIInfo(schema.Lax):
    release_url: str | None = None
    project_url: str | None = None


class PyPIResponse(schema.Lax):
    urls: list[PyPIUrl] = pydantic.Field(default_factory=list)
    info: PyPIInfo = pydantic.Field(default_factory=PyPIInfo)


class DeleteData(schema.Lax):
    release_name: str
    platform: sql.DistributionPlatform
    owner_namespace: str
    package: str
    version: str

    @pydantic.field_validator("platform", mode="before")
    @classmethod
    def coerce_platform(cls, v: object) -> object:
        if isinstance(v, str):
            return sql.DistributionPlatform[v]
        return v


# Lax to ignore csrf_token and submit
# WTForms types platform as Any, which is insufficient
# And this way we also get nice JSON from the Pydantic model dump
# Including all of the enum properties
class Data(schema.Lax):
    platform: sql.DistributionPlatform
    owner_namespace: str | None = None
    package: str
    version: str
    details: bool

    @pydantic.field_validator("owner_namespace", mode="before")
    @classmethod
    def empty_to_none(cls, v):
        return None if v is None or (isinstance(v, str) and v.strip() == "") else v
