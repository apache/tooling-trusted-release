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
