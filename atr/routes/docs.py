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
from html.parser import HTMLParser

import aiofiles
import aiofiles.os
import markupsafe
import quart

import atr.config as config
import atr.route as route
import atr.template as template


class H1Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.h1_content: str | None = None
        self._in_h1 = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if (tag == "h1") and (self.h1_content is None):
            self._in_h1 = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "h1":
            self._in_h1 = False

    def handle_data(self, data: str) -> None:
        if self._in_h1 and (self.h1_content is None):
            self.h1_content = data.strip()


@route.public("/docs/")
async def index(session: route.CommitterSession | None) -> str:
    return await _serve_docs_page("index")


@route.public("/docs/<path:page>")
async def page(session: route.CommitterSession | None, page: str) -> str:
    return await _serve_docs_page(page)


async def _serve_docs_page(page: str) -> str:
    docs_dir = pathlib.Path(config.get().PROJECT_ROOT) / "atr" / "docs"

    if not page.endswith(".html"):
        page = f"{page}.html"

    file_path = docs_dir / page

    docs_root = docs_dir.resolve()
    try:
        resolved_file = file_path.resolve()
    except FileNotFoundError:
        quart.abort(404)
    try:
        resolved_file.relative_to(docs_root)
    except ValueError:
        quart.abort(404)

    if not await aiofiles.os.path.exists(resolved_file):
        quart.abort(404)

    if not await aiofiles.os.path.isfile(resolved_file):
        quart.abort(404)

    async with aiofiles.open(resolved_file, encoding="utf-8") as handle:
        html_content = await handle.read()

    safe_content = markupsafe.Markup(html_content)

    filename_title = resolved_file.stem.replace("-", " ").replace("_", " ").title()
    try:
        parser = H1Parser()
        first_lines = "\n".join(html_content.split("\n")[:8])
        parser.feed(first_lines)
        title = parser.h1_content or filename_title
    except Exception:
        title = filename_title

    return await template.blank(title=title, content=safe_content)
