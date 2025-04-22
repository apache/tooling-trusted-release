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

import atr.db.models as models
import atr.routes.candidate as candidate
import atr.routes.draft as draft
import atr.routes.preview as preview
import atr.util as util


def release_as_url(release: models.Release) -> str:
    if release.phase.value == "release_candidate_draft":
        return util.as_url(draft.compose, project_name=release.project.name, version_name=release.version)
    elif release.phase.value == "release_candidate":
        resolve_release = candidate.resolve_release  # type: ignore[has-type]
        return util.as_url(resolve_release, project_name=release.project.name, version_name=release.version)
    elif release.phase.value == "release_preview":
        announce_release = preview.announce_release  # type: ignore[has-type]
        return util.as_url(announce_release, project_name=release.project.name, version_name=release.version)
    else:
        raise ValueError(f"Unknown release phase: {release.phase}")
