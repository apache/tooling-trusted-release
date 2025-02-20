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

from atr.apache import CommitteeInfo, CommitteeRetired, LDAPProjects


def test_ldap_projects_model():
    json_data = """
{
  "lastTimestamp": "20250219115218Z",
  "project_count": 1,
  "projects": {
    "tooling": {
      "createTimestamp": "20170713020428Z",
      "modifyTimestamp": "20240725001829Z",
      "member_count": 3,
      "owner_count": 3,
      "members": [
        "wave",
        "sbp",
        "tn"
      ],
      "owners": [
        "wave",
        "sbp",
        "tn"
      ]
    }
  }
}"""
    projects = LDAPProjects.model_validate(json.loads(json_data))

    assert projects is not None
    assert projects.project_count == 1
    assert projects.projects[0].name == "tooling"


def test_committee_info_model():
    json_data = """
{
  "last_updated": "2025-02-19 21:57:21 UTC",
  "committee_count": 1,
  "pmc_count": 1,
  "committees": {
    "tooling": {
      "display_name": "Tooling",
      "site": "http://tooling.apache.org/",
      "description": "tools, tools, tools",
      "mail_list": "tooling",
      "established": "01/2025",
      "report": [
        "January",
        "April",
        "July",
        "October"
      ],
      "chair": {
        "wave": {
          "name": "Dave Fisher"
        }
      },
      "roster_count": 3,
      "roster": {
        "wave": {
          "name": "Dave Fisher",
          "date": "2025-01-01"
        },
        "sbp": {
          "name": "Sean B. Palmer",
          "date": "2025-02-01"
        },
        "tn": {
          "name": "Thomas Neidhart",
          "date": "2025-03-01"
        }
      },
      "pmc": true
    }
  }
}"""
    committees = CommitteeInfo.model_validate(json.loads(json_data))

    assert committees is not None
    assert committees.pmc_count == 1

    tooling = committees.committees[0]
    assert tooling.name == "tooling"
    assert len(tooling.roster) == 3
    assert "tn" in map(lambda x: x.id, tooling.roster)


def test_committee_retired_model():
    json_data = """
{
  "last_updated": "2025-02-19 21:57:21 UTC",
  "retired_count": 1,
  "retired": {
    "abdera": {
      "display_name": "Abdera",
      "description": "blablabla",
      "retired": "2017-03"
    }
  }
}"""
    retired_committees = CommitteeRetired.model_validate(json.loads(json_data))

    assert retired_committees is not None
    assert retired_committees.retired_count == 1

    pmc = retired_committees.retired[0]
    assert pmc.name == "abdera"
