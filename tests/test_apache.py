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

from atr.apache import ApacheProjects


def test_model():
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
    projects = ApacheProjects.model_validate(json.loads(json_data))

    assert projects is not None
    assert projects.project_count == 1
    assert projects.projects[0].name == "tooling"
