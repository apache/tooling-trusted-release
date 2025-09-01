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

import asyncio
import json
import os
import sys

import aiohttp

URL = "https://api.github.com/graphql"
Q = """
query($owner:String!,$name:String!,$after:String){
  repository(owner:$owner,name:$name){
    refs(refPrefix:"refs/tags/",first:100,after:$after,orderBy:{field:TAG_COMMIT_DATE,direction:DESC}){
      pageInfo{hasNextPage endCursor}
      nodes{
        name
        target{
          __typename oid
          ... on Commit{committedDate}
          ... on Tag{
            target{
              __typename oid
              ... on Commit{committedDate}
            }
          }
        }
      }
    }
  }
}
"""


def repo_from_arg(a: str) -> tuple[str, str]:
    # Allow either owner/repo or owner repo
    return (a.split("/", 1)[0], a.split("/", 1)[1]) if "/" in a else (a, sys.argv[2])


def pick(node: dict) -> tuple[str, str, str] | None:
    # Pick the tag, commit, and committedDate from the node
    t = node["target"]
    if t["__typename"] == "Commit":
        return node["name"], t["oid"], t["committedDate"]
    if t["__typename"] == "Tag":
        tt = t.get("target") or {}
        if tt.get("__typename") == "Commit":
            return node["name"], tt["oid"], tt["committedDate"]
    return None


async def page(s, aft, owner, name):
    v = {"owner": owner, "name": name, "after": aft}
    async with s.post(URL, json={"query": Q, "variables": v}) as r:
        r.raise_for_status()
        return await r.json()


def hdr(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}", "Accept": "application/json", "User-Agent": "tags-min"}


async def run(owner: str, name: str, tok: str):
    out = {}
    async with aiohttp.ClientSession(headers=hdr(tok)) as s:
        aft = None
        while True:
            data = await page(s, aft, owner, name)
            repo = data["data"]["repository"]
            refs = repo["refs"]
            for n in refs["nodes"]:
                row = pick(n)
                if row:
                    # Sometimes they use cyclonedx-maven-plugin-x.y.z, and sometimes x.y.z
                    # The more consistent one is the former, so we filter out the latter
                    if not row[0].startswith("cyclonedx-maven-plugin-"):
                        continue
                    # We discard the commit hash, which is row[1]
                    committed_date = row[2]
                    if committed_date in out:
                        raise SystemExit(f"duplicate committedDate: {committed_date}")
                    version = row[0].removeprefix("cyclonedx-maven-plugin-")
                    out[committed_date] = version
            if not refs["pageInfo"]["hasNextPage"]:
                break
            aft = refs["pageInfo"]["endCursor"]
    print(json.dumps(out, ensure_ascii=False, indent=2))


def main() -> None:
    if not os.getenv("GITHUB_TOKEN"):
        raise SystemExit("set GITHUB_TOKEN")
    if len(sys.argv) < 2:
        raise SystemExit("usage: github_tag_dates.py owner/repo")
    owner, name = repo_from_arg(sys.argv[1])
    asyncio.run(run(owner, name, os.environ["GITHUB_TOKEN"]))


if __name__ == "__main__":
    main()
