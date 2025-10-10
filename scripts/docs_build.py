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
from typing import NamedTuple


class TocEntry(NamedTuple):
    number: str
    title: str
    path: str
    level: int
    parent: str | None


class Navigation(NamedTuple):
    up: tuple[str, str] | None
    prev: tuple[str, str, str] | None
    next: tuple[str, str, str] | None
    children: list[TocEntry]


def parse_toc_line(line: str) -> TocEntry | None:
    pattern = r"^(\s*)\*\s+`([^`]+)`\s+\[([^\]]+)\]\(([^)]+)\)"
    match = re.match(pattern, line)
    if not match:
        return None

    indent, number, title, path = match.groups()
    level = len(indent) // 2
    number_clean = number.strip()

    number_no_dots = number_clean.rstrip(".")
    parts = number_no_dots.split(".")

    if level == 0:
        parent = None
    else:
        parent = ".".join(parts[:-1])

    return TocEntry(number_clean, title, path, level, parent)


def parse_toc(index_path: pathlib.Path) -> list[TocEntry]:
    content = index_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    in_toc = False
    entries = []

    for line in lines:
        if line.strip() == "## Table of contents":
            in_toc = True
            continue
        if in_toc:
            if line.strip() and (not line.startswith("*")) and (not line.startswith(" ")):
                break
            entry = parse_toc_line(line)
            if entry:
                entries.append(entry)

    return entries


def validate_files(docs_dir: pathlib.Path, entries: list[TocEntry]) -> None:
    referenced_files = {entry.path + ".md" for entry in entries}
    referenced_files.add("index.md")

    existing_files = {f.name for f in docs_dir.glob("*.md")}

    missing = referenced_files - existing_files
    if missing:
        print(f"Error: TOC references files that don't exist: {missing}", file=sys.stderr)
        sys.exit(1)

    unreferenced = existing_files - referenced_files
    if unreferenced:
        print(f"Error: Markdown files exist that are not in TOC: {unreferenced}", file=sys.stderr)
        sys.exit(1)


def build_navigation(entries: list[TocEntry]) -> dict[str, Navigation]:
    nav_map = {}

    for i, entry in enumerate(entries):
        if entry.level == 0:
            up = ("Documentation", ".")
        else:
            parent_entry = next(e for e in entries if e.number.rstrip(".") == entry.parent)
            up = (f"{parent_entry.number} {parent_entry.title}", parent_entry.path)

        prev_entry = None
        for j in range(i - 1, -1, -1):
            if entries[j].level == entry.level:
                prev_entry = entries[j]
                break

        next_entry = None
        for j in range(i + 1, len(entries)):
            if entries[j].level == entry.level:
                next_entry = entries[j]
                break

        if prev_entry:
            prev = (prev_entry.number, prev_entry.title, prev_entry.path)
        else:
            prev = None

        if next_entry:
            next_nav = (next_entry.number, next_entry.title, next_entry.path)
        else:
            next_nav = None

        entry_number_no_dots = entry.number.rstrip(".")
        children = [e for e in entries if e.parent == entry_number_no_dots]

        nav_map[entry.path] = Navigation(up, prev, next_nav, children)

    return nav_map


def extract_h2_headings(content: str) -> list[tuple[str, str]]:
    lines = content.splitlines()
    headings = []

    for line in lines:
        match = re.match(r"^##\s+(.+)$", line)
        if match:
            title = match.group(1)
            anchor = title.lower()
            anchor = re.sub(r"^\d+\.\s*", "", anchor)
            anchor = re.sub(r"[^\w\s-]", "", anchor)
            anchor = re.sub(r"[\s_]+", "-", anchor)
            anchor = anchor.strip("-")
            headings.append((title, anchor))

    return headings


def generate_navigation_block(entry: TocEntry, nav: Navigation, h2_headings: list[tuple[str, str]]) -> str:
    blocks = []

    if nav.up is not None:
        up_text = nav.up[0]
        up_parts = up_text.split(" ", 1)
        if (len(up_parts) == 2) and (up_parts[0].rstrip(".").replace(".", "").isdigit()):
            blocks.append(f"**Up**: `{up_parts[0]}` [{up_parts[1]}]({nav.up[1]})")
        else:
            blocks.append(f"**Up**: [{up_text}]({nav.up[1]})")
        blocks.append("")

    if nav.prev is not None:
        blocks.append(f"**Prev**: `{nav.prev[0]}` [{nav.prev[1]}]({nav.prev[2]})")
    else:
        blocks.append("**Prev**: (none)")
    blocks.append("")

    if nav.next is not None:
        blocks.append(f"**Next**: `{nav.next[0]}` [{nav.next[1]}]({nav.next[2]})")
    else:
        blocks.append("**Next**: (none)")
    blocks.append("")

    if nav.children:
        blocks.append("**Pages**:")
        blocks.append("")
        for child in nav.children:
            indent = "  " * (child.level - entry.level - 1)
            blocks.append(f"{indent}* `{child.number}` [{child.title}]({child.path})")
        blocks.append("")

    if h2_headings:
        blocks.append("**Sections**:")
        blocks.append("")
        for title, anchor in h2_headings:
            blocks.append(f"* [{title}](#{anchor})")
        blocks.append("")

    return "\n".join(blocks)


def update_document(docs_dir: pathlib.Path, entry: TocEntry, nav: Navigation) -> None:
    file_path = docs_dir / f"{entry.path}.md"
    content = file_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    h2_headings = extract_h2_headings(content)

    first_h2_index = None
    for i, line in enumerate(lines):
        if re.match(r"^##\s+", line):
            first_h2_index = i
            break

    if first_h2_index is None:
        print(f"Warning: {entry.path}.md has no h2 sections", file=sys.stderr)
        content_lines = lines
    else:
        content_lines = lines[first_h2_index:]

    new_heading = f"# {entry.number} {entry.title}"
    nav_block = generate_navigation_block(entry, nav, h2_headings)

    new_lines = [new_heading, "", nav_block, *content_lines]

    new_content = "\n".join(new_lines)
    if not new_content.endswith("\n"):
        new_content += "\n"

    file_path.write_text(new_content, encoding="utf-8")


def main() -> None:
    docs_dir = pathlib.Path("atr/docs")
    index_path = docs_dir / "index.md"

    if not index_path.exists():
        print(f"Error: {index_path} not found", file=sys.stderr)
        sys.exit(1)

    entries = parse_toc(index_path)
    if not entries:
        print("Error: No TOC entries found in index.md", file=sys.stderr)
        sys.exit(1)

    validate_files(docs_dir, entries)

    nav_map = build_navigation(entries)

    for entry in entries:
        update_document(docs_dir, entry, nav_map[entry.path])

    print(f"Updated {len(entries)} documentation files")


if __name__ == "__main__":
    main()
