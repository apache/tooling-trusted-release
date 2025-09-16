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

import atr.route as route
import atr.util as util


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


async def _directory_listing(full_path: pathlib.Path, current_path: str) -> quart.Response:
    html_parts = [
        "<!doctype html>",
        f"<title>Index of /{current_path}</title>",
        "<style>body { margin: 1rem; }</style>",
        f"<h1>Index of /{current_path}</h1>",
        "<pre>",
    ]

    if current_path:
        parent_path = pathlib.Path(current_path).parent
        parent_url_path = str(parent_path) if str(parent_path) != "." else ""
        if parent_url_path:
            html_parts.append(f'<a href="{util.as_url(path, path=parent_url_path)}">../</a>')
        else:
            html_parts.append(f'<a href="{util.as_url(root)}">../</a>')

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
            link = f'<a href="{util.as_url(path, path=entry_path)}">{display_name}</a>'
            html_parts.append(f"{mode} {nlink} {size} {mtime}  {link}")

    html_parts.append("</pre>")
    return quart.Response("\n".join(html_parts), mimetype="text/html")


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
