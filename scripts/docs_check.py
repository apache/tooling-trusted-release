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

import pathlib
import re
import sys
from typing import Final, NamedTuple

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import docs_post_process as post_process


class Link(NamedTuple):
    source_file: str
    line_number: int
    text: str
    target: str
    anchor: str | None


class Heading(NamedTuple):
    text: str
    anchor: str


# TODO: Should think more about whether scripts should use the _ convention or not
# The rationale for using it is that then we can port to non-script code more easily
# But for scripts *per se*, it does not make sense


_LINK_PATTERN: Final = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_HEADING_PATTERN: Final = re.compile(r"^#+\s+(.+)$")


def _extract_links(file_path: pathlib.Path) -> list[Link]:
    content = file_path.read_text(encoding="utf-8")
    lines = content.splitlines()
    links = []

    for line_number, line in enumerate(lines, start=1):
        for match in _LINK_PATTERN.finditer(line):
            text = match.group(1)
            target = match.group(2)

            if target.startswith("/ref/"):
                continue

            if target.startswith("http://") or target.startswith("https://"):
                continue

            anchor = None
            if "#" in target:
                target, anchor = target.split("#", 1)

            links.append(Link(file_path.name, line_number, text, target, anchor))

    return links


def _extract_headings(file_path: pathlib.Path) -> list[Heading]:
    content = file_path.read_text(encoding="utf-8")
    lines = content.splitlines()
    headings = []

    for line in lines:
        match = _HEADING_PATTERN.match(line)
        if match:
            text = match.group(1)
            anchor = post_process.generate_heading_id(text)
            headings.append(Heading(text, anchor))

    return headings


def _validate_links(docs_dir: pathlib.Path, all_links: list[Link]) -> list[str]:
    errors = []
    existing_files = {f.stem for f in docs_dir.glob("*.md")}
    heading_cache: dict[str, set[str]] = {}

    for link in all_links:
        if link.target == ".":
            target_file = "index"
        elif link.target:
            if link.target.endswith(".html"):
                errors.append(
                    f"{link.source_file}:{link.line_number}: Link should not include '.html' extension: '{link.target}'"
                )
                target_file = link.target.removesuffix(".html")
            else:
                target_file = link.target
        else:
            target_file = link.source_file.replace(".md", "")

        if target_file not in existing_files:
            errors.append(
                f"{link.source_file}:{link.line_number}: "
                f"Link to non-existent file '{link.target}' "
                f"(expected {target_file}.md)"
            )
            continue

        if link.anchor:
            if target_file not in heading_cache:
                target_path = docs_dir / f"{target_file}.md"
                headings = _extract_headings(target_path)
                heading_cache[target_file] = {h.anchor for h in headings}

            if link.anchor not in heading_cache[target_file]:
                errors.append(
                    f"{link.source_file}:{link.line_number}: "
                    f"Link to non-existent anchor '#{link.anchor}' in '{target_file}'"
                )

    return errors


def main() -> None:
    docs_dir = pathlib.Path("atr/docs")

    if not docs_dir.exists():
        print(f"Error: {docs_dir} not found", file=sys.stderr)
        sys.exit(1)

    all_links = []
    for md_file in docs_dir.glob("*.md"):
        links = _extract_links(md_file)
        all_links.extend(links)

    errors = _validate_links(docs_dir, all_links)

    if errors:
        print("Documentation link validation errors:\n", file=sys.stderr)
        for error in errors:
            print(error, file=sys.stderr)
        print(f"\nFound {len(errors)} error(s)", file=sys.stderr)
        sys.exit(1)

    print(f"Validated {len(all_links)} links across {len(list(docs_dir.glob('*.md')))} files")
    print("All links are valid")


if __name__ == "__main__":
    main()
