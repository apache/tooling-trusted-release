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

import atr.routes.announce as announce
import atr.routes.candidate as candidate
import atr.routes.committees as committees
import atr.routes.compose as compose
import atr.routes.distribution as distribution
import atr.routes.download as download
import atr.routes.draft as draft
import atr.routes.file as file
import atr.routes.finish as finish
import atr.routes.ignores as ignores
import atr.routes.keys as keys
import atr.routes.preview as preview
import atr.routes.projects as projects
import atr.routes.published as published
import atr.routes.release as release
import atr.routes.report as report
import atr.routes.resolve as resolve
import atr.routes.revisions as revisions
import atr.routes.root as root
import atr.routes.sbom as sbom
import atr.routes.start as start
import atr.routes.tokens as tokens
import atr.routes.upload as upload
import atr.routes.vote as vote
import atr.routes.voting as voting

__all__ = [
    "announce",
    "candidate",
    "committees",
    "compose",
    "distribution",
    "download",
    "draft",
    "file",
    "finish",
    "ignores",
    "keys",
    "preview",
    "projects",
    "published",
    "release",
    "report",
    "resolve",
    "revisions",
    "root",
    "sbom",
    "start",
    "tokens",
    "upload",
    "vote",
    "voting",
]


# Export data for a custom linter script
def _export_routes() -> None:
    import asyncio

    async def _export_routes_async() -> None:
        """Export all routes to a JSON file for static analysis."""
        import json
        import sys

        import aiofiles

        route_paths: list[str] = []
        current_module = sys.modules[__name__]

        for module_name in dir(current_module):
            if module_name.startswith("_"):
                # Not intended for external use
                continue

            module = getattr(current_module, module_name)
            if not hasattr(module, "__file__"):
                # Not a module
                continue

            # Get all callable interfaces that do not begin with an underscore
            for attr_name in dir(module):
                if attr_name.startswith("_"):
                    # Not intended for external use
                    continue
                if not callable(getattr(module, attr_name)):
                    # Not callable
                    continue
                route_path = f"{module_name}.{attr_name}"
                route_paths.append(route_path)

        async with aiofiles.open("routes.json", "w", encoding="utf-8") as f:
            await f.write(json.dumps(route_paths, indent=2))

    loop = asyncio.get_event_loop()
    loop.run_until_complete(_export_routes_async())


_export_routes()
del _export_routes
