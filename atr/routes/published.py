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

import pathlib
import stat
from datetime import datetime

import aiofiles.os
import quart

import atr.htm as htm
import atr.route as route
import atr.util as util
import atr.web as web


@route.committer("/published/<path:path>")
async def path(session: route.CommitterSession, path: str) -> quart.Response:
    """View the content of a specific file in the downloads directory."""
    # This route is for debugging
    # When developing locally, there is no proxy to view the downloads directory
    # Therefore this path acts as a way to check the contents of that directory
    return await _path(session, path)


@route.committer("/published/")
async def root(session: route.CommitterSession) -> quart.Response:
    return await _path(session, "")


async def _directory_listing(full_path: pathlib.Path, current_path: str) -> web.ElementResponse:
    html = htm.Block(htm.html)
    html.title[f"Index of /{current_path}"]
    html.style["body { margin: 1rem; }"]
    with html.block(htm.body) as body:
        htm.h1[f"Index of /{current_path}"]
        with body.block(htm.pre) as pre:
            await _directory_listing_pre(full_path, current_path, pre)
    return web.ElementResponse(html.collect())


async def _directory_listing_pre(full_path: pathlib.Path, current_path: str, pre: htm.Block) -> None:
    if current_path:
        parent_path = pathlib.Path(current_path).parent
        parent_url_path = str(parent_path) if str(parent_path) != "." else ""
        if parent_url_path:
            pre.a(href=util.as_url(path, path=parent_url_path))["../"]
        else:
            pre.a(href=util.as_url(root))["../"]
        pre.text("\n\n")

    entries = []
    dir_contents = await aiofiles.os.listdir(full_path)
    for name in dir_contents:
        try:
            stat_result = await aiofiles.os.stat(full_path / name)
            entries.append({"name": name, "stat": stat_result})
        except OSError:
            continue
    entries.sort(key=lambda e: (not stat.S_ISDIR(e["stat"].st_mode), e["name"].lower()))

    if entries:
        max_nlink_len = max(len(str(e["stat"].st_nlink)) for e in entries)
        max_size_len = max(len(str(e["stat"].st_size)) for e in entries)

        for entry in entries:
            stat_info = entry["stat"]
            is_dir = stat.S_ISDIR(stat_info.st_mode)
            mode = stat.filemode(stat_info.st_mode)
            nlink = str(stat_info.st_nlink).rjust(max_nlink_len)
            size = str(stat_info.st_size).rjust(max_size_len)
            mtime = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M")
            entry_path = str(pathlib.Path(current_path) / entry["name"])
            display_name = f"{entry['name']}/" if is_dir else entry["name"]
            pre.text(f"{mode} {nlink} {size} {mtime}  ")
            pre.a(href=util.as_url(path, path=entry_path))[display_name]
            pre.text("\n")


async def _file_content(full_path: pathlib.Path) -> quart.Response:
    return await quart.send_file(full_path)


async def _path(session: route.CommitterSession, path: str) -> quart.Response:
    downloads_path = util.get_downloads_dir()
    full_path = downloads_path / path
    if await aiofiles.os.path.isdir(full_path):
        return await _directory_listing(full_path, path)

    if await aiofiles.os.path.isfile(full_path):
        return await _file_content(full_path)

    return quart.abort(404)
