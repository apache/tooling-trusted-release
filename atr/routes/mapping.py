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
import atr.routes.compose as compose
import atr.routes.finish as finish
import atr.routes.release as routes_release
import atr.routes.vote as vote
import atr.util as util


def release_as_url(release: models.Release) -> str:
    match release.phase:
        case models.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
            return util.as_url(compose.selected, project_name=release.project.name, version_name=release.version)
        case models.ReleasePhase.RELEASE_CANDIDATE:
            return util.as_url(vote.selected, project_name=release.project.name, version_name=release.version)
        case models.ReleasePhase.RELEASE_PREVIEW:
            return util.as_url(finish.selected, project_name=release.project.name, version_name=release.version)
        case models.ReleasePhase.RELEASE:
            completed = routes_release.completed  # type: ignore[has-type]
            return util.as_url(completed, project_name=release.project.name)
