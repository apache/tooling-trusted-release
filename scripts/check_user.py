#!/usr/bin/env python3

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
import sys

import atr.principal as principal


async def get_user_memberships(asf_uid: str) -> dict[str, str | list[str]]:
    try:
        auth = await principal.Authorisation(asf_uid)
        member_of = auth.member_of()
        participant_of = auth.participant_of()
        participant_only = participant_of - member_of
        return {"member_of": sorted(member_of), "participant_of": sorted(participant_only)}
    except principal.AuthenticationError as e:
        return {"error": str(e), "member_of": [], "participant_of": []}


async def main():
    if len(sys.argv) < 2:
        print("Usage: python check_user.py <asf_uid>")
        sys.exit(1)

    asf_uid = sys.argv[1]
    result = await get_user_memberships(asf_uid)

    if "error" in result:
        print(f"Error: {result['error']}")
        return

    print("## member of")
    if result["member_of"]:
        for committee in result["member_of"]:
            print(committee)
    else:
        print()

    print()
    print("## participant of")
    if result["participant_of"]:
        for committee in result["participant_of"]:
            print(committee)
    else:
        print()


if __name__ == "__main__":
    asyncio.run(main())
