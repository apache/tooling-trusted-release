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

# find atr -name '*.py' -exec python3 scripts/markup_strings.py {} \; | grep -v '^ok '
# TODO: Detect instances of "| safe" in HTML templates

import ast
import enum
import pathlib
import re
import sys

_EMAIL_PATTERN = re.compile(r"<[^>]*@[^>]*>")
_MARKUP_PATTERN = re.compile(r'</?[A-Za-z]|[A-Za-z]="')


class ExitCode(enum.IntEnum):
    SUCCESS = 0
    FAILURE = 1
    USAGE_ERROR = 2


class MarkupStringVisitor(ast.NodeVisitor):
    def __init__(self, filename: str) -> None:
        super().__init__()
        self.filename: str = filename
        self.matches: list[tuple[int, int, str]] = []

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            if _MARKUP_PATTERN.search(node.value):
                is_okay = "(?P<" in node.value
                is_okay |= node.value.startswith("/") and ("/<" in node.value)
                is_okay |= _EMAIL_PATTERN.search(node.value) is not None
                if not is_okay:
                    self.matches.append((node.lineno, node.col_offset, node.value))
        self.generic_visit(node)


def _parse_python_code(code: str, filename: str) -> ast.Module | None:
    try:
        return ast.parse(code, filename=filename)
    except SyntaxError as e:
        print(f"!! {filename} - invalid syntax: {e}", file=sys.stderr)
        return None


def _read_file_content(file_path: pathlib.Path) -> str | None:
    try:
        return file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"!! {file_path} - file not found", file=sys.stderr)
        return None
    except OSError:
        print(f"!! {file_path} - could not read file", file=sys.stderr)
        return None


def main() -> None:
    quiet = sys.argv[2:3] == ["--quiet"]
    argc = len(sys.argv)
    match (argc, quiet):
        case (2, False):
            ...
        case (3, True):
            ...
        case _:
            print(f"Usage: {sys.argv[0]} <filename.py> [ --quiet ]", file=sys.stderr)
            sys.exit(ExitCode.USAGE_ERROR)

    file_path = pathlib.Path(sys.argv[1])
    filename = str(file_path)

    # if filename == "atr/htm.py":
    #     print(f"!! {filename} - ignored", file=sys.stderr)
    #     sys.exit(ExitCode.SUCCESS)

    if not file_path.is_file() or (not filename.endswith(".py")):
        print(f"!! {filename} - invalid file", file=sys.stderr)
        sys.exit(ExitCode.USAGE_ERROR)

    content = _read_file_content(file_path)
    if content is None:
        sys.exit(ExitCode.FAILURE)

    tree = _parse_python_code(content, filename)
    if tree is None:
        sys.exit(ExitCode.FAILURE)

    visitor = MarkupStringVisitor(filename)
    visitor.visit(tree)

    if visitor.matches:
        for lineno, _col, string_value in visitor.matches:
            print(f"{filename}:{lineno}: {string_value!r}")
        sys.exit(ExitCode.FAILURE)
    else:
        if not quiet:
            print(f"ok {filename}")
        sys.exit(ExitCode.SUCCESS)


if __name__ == "__main__":
    main()
