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

import json
import os
from typing import Any

from atr.datasources.apache import (
    CommitteeData,
    GroupsData,
    LDAPProjectsData,
    PodlingsData,
    ProjectsData,
    RetiredCommitteeData,
)


def _load_test_data(name: str) -> Any:
    with open(os.path.join(os.path.dirname(__file__), "testdata", f"{name}.json")) as f:
        return json.load(f)


def test_ldap_projects_data_model():
    projects = LDAPProjectsData.model_validate(_load_test_data("ldap_projects"))

    assert projects is not None
    assert projects.project_count == 1
    assert projects.projects[0].name == "tooling"


def test_committee_data_model():
    committees = CommitteeData.model_validate(_load_test_data("committees"))

    assert committees is not None
    assert committees.pmc_count == 1

    tooling = committees.committees[0]
    assert tooling.name == "tooling"
    assert len(tooling.roster) == 3
    assert "tn" in map(lambda x: x.id, tooling.roster)

    assert len(tooling.chair) == 1
    assert "wave" in map(lambda x: x.id, tooling.chair)


def test_retired_committee_data_model():
    retired_committees = RetiredCommitteeData.model_validate(_load_test_data("retired_committees"))

    assert retired_committees is not None
    assert retired_committees.retired_count == 1

    pmc = retired_committees.retired[0]
    assert pmc.name == "abdera"


def test_podlings_data_model():
    podlings = PodlingsData.model_validate(_load_test_data("podlings"))

    assert len(podlings) == 1
    podling = podlings.get("amoro")
    assert podling is not None
    assert podling.name == "Apache Amoro (Incubating)"


def test_groups_data_model():
    groups = GroupsData.model_validate(_load_test_data("groups"))

    assert len(groups) == 2
    assert groups.get("accumulo") is not None
    assert groups.get("accumulo-pmc") is not None


def test_projects_data_model():
    projects = ProjectsData.model_validate(_load_test_data("projects"))

    assert len(projects) == 1
    assert projects.get("accumulo") is not None
