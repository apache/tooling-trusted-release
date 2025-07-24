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

import os
import pathlib
import urllib.parse
from typing import TYPE_CHECKING, Final

import asfpy.pubsub

import atr.log as log
import atr.svn as svn

if TYPE_CHECKING:
    from collections.abc import Sequence

# TODO: Check that these prefixes are correct
_WATCHED_PREFIXES: Final[tuple[str, ...]] = (
    "/svn/dist/dev",
    "/svn/dist/release",
)


class SVNListener:
    def __init__(
        self,
        working_copy_root: os.PathLike | str,
        url: str,
        username: str,
        password: str,
        topics: str = "commit/svn",
    ) -> None:
        self.working_copy_root = pathlib.Path(working_copy_root)
        self.url = url
        self.username = username
        self.password = password
        self.topics = topics

    async def start(self) -> None:
        """Run forever, processing PubSub payloads as they arrive."""
        # TODO: Add reconnection logic here?
        # Or does asfpy.pubsub.listen() already do this?
        log.info("SVNListener.start() called")
        async for payload in asfpy.pubsub.listen(
            # TODO: Upstream this change to BAT
            urllib.parse.urljoin(self.url, self.topics),
            username=self.username,
            password=self.password,
        ):
            if (payload is None) or ("stillalive" in payload):
                continue

            pubsub_path = str(payload.get("pubsub_path", ""))
            if not pubsub_path.startswith(_WATCHED_PREFIXES):
                # Ignore commits outside dist/dev or dist/release
                continue

            log.debug("PubSub payload: %s", payload)
            await self._process_payload(payload)
        log.info("SVNListener.start() finished")

    async def _process_payload(self, payload: dict) -> None:
        """
        Update each changed file in the local working copy.

        Payload format that we listen to:
            {
              "commit": {
                 "changed": ["/path/inside/repo/foo.txt", ...]
              },
              ...
            }
        """
        changed: Sequence[str] = payload.get("commit", {}).get("changed", [])
        for repo_path in changed:
            prefix = next((p for p in _WATCHED_PREFIXES if repo_path.startswith(p)), "")
            if not prefix:
                continue
            local_path = self.working_copy_root / repo_path[len(prefix) :].lstrip("/")
            try:
                await svn.update(local_path)
                log.info("svn updated %s", local_path)
            except Exception as exc:
                log.warning("failed svn update %s: %s", local_path, exc)
