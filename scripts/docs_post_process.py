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

import html
import html.parser as parser
import pathlib
import re
import sys


def generate_heading_id(text: str) -> str:
    text = re.sub(r"^[\d.]+\s*", "", text)
    text = text.lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    text = text.strip("-")
    return text


class HeadingProcessor(parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.output: list[str] = []
        self.current_pos = 0
        self.in_heading = False
        self.heading_tag = ""
        self.heading_content = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        text = self.get_starttag_text()
        if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            existing_id = dict(attrs).get("id")
            if not existing_id:
                self.in_heading = True
                self.heading_tag = tag
                self.heading_content = ""
            elif text is not None:
                self.output.append(text)
        elif text is not None:
            self.output.append(text)

    def handle_endtag(self, tag: str) -> None:
        if self.in_heading and tag == self.heading_tag:
            heading_id = self._generate_id(self.heading_content)
            self.output.append(f'<{self.heading_tag} id="{heading_id}">')
            self.output.append(self.heading_content)
            self.output.append(f"</{self.heading_tag}>")
            self.in_heading = False
            self.heading_tag = ""
            self.heading_content = ""
        else:
            self.output.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if self.in_heading:
            self.heading_content += data
        else:
            self.output.append(html.escape(data, quote=False))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        text = self.get_starttag_text()
        if text is not None:
            self.output.append(text)

    def _generate_id(self, text: str) -> str:
        return generate_heading_id(text)

    def get_html(self) -> str:
        return "".join(self.output)


def process_html_file(file_path: pathlib.Path) -> None:
    html_content = file_path.read_text(encoding="utf-8")

    parser = HeadingProcessor()
    parser.feed(html_content)

    processed_html = parser.get_html()
    file_path.write_text(processed_html, encoding="utf-8")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python docs_post_process.py <html_file> [<html_file> ...]")
        sys.exit(1)

    for file_arg in sys.argv[1:]:
        file_path = pathlib.Path(file_arg)
        if file_path.exists() and file_path.suffix == ".html":
            process_html_file(file_path)
        else:
            print(f"Warning: {file_arg} not found or not an HTML file")


if __name__ == "__main__":
    main()
