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

# TODO: We want to go the other way around too
# In other words, finding underscoreless functions which are not accesssed externally

import ast
import enum
import pathlib
import sys

ALLOWED_PRIVATE_ACCESS: dict[str, set[str]] = {
    "atr/htm.py": {"new_element._attrs"},
    "atr/models/sql.py": {"Release._latest_revision_number"},
    "atr/tarzip.py": {"member_wrapper._original_info"},
}


class ExitCode(enum.IntEnum):
    """Exit codes for the script."""

    SUCCESS = 0
    FAILURE = 1
    USAGE_ERROR = 2


class PrivateAccessVisitor(ast.NodeVisitor):
    """Visits AST nodes to find external access to private attributes."""

    def __init__(self, filename: str) -> None:
        """Construct a visitor."""
        super().__init__()
        self.filename: str = filename
        self.violations: list[tuple[int, int, str]] = []

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Visits ast.Attribute nodes."""
        # Check whether the attribute name starts with a single underscore
        if node.attr.startswith("_") and (not node.attr.startswith("__")):
            # Exclude "cls" and "self"
            if isinstance(node.value, ast.Name) and (node.value.id not in {"cls", "self"}):
                accessed_name = f"{node.value.id}.{node.attr}"
                allowed_access = ALLOWED_PRIVATE_ACCESS.get(self.filename, set())
                if accessed_name not in allowed_access:
                    self.violations.append((node.lineno, node.col_offset, accessed_name))
        self.generic_visit(node)


def _parse_python_code(code: str, filename: str) -> ast.Module | None:
    """Parses Python code string into an AST module."""
    try:
        return ast.parse(code, filename=filename)
    except SyntaxError as e:
        print(f"!! {filename} - invalid syntax: {e}", file=sys.stderr)
        return None


def _read_file_content(file_path: pathlib.Path) -> str | None:
    """Reads the content of a file."""
    try:
        return file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"!! {file_path} - file not found", file=sys.stderr)
        return None
    except OSError:
        print(f"!! {file_path} - could not read file", file=sys.stderr)
        return None


def main() -> None:
    """Main entry point for the script."""
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

    if not file_path.is_file() or (not filename.endswith(".py")):
        print(f"!! {filename} - invalid file", file=sys.stderr)
        sys.exit(ExitCode.USAGE_ERROR)

    content = _read_file_content(file_path)
    if content is None:
        sys.exit(ExitCode.FAILURE)

    tree = _parse_python_code(content, filename)
    if tree is None:
        sys.exit(ExitCode.FAILURE)

    visitor = PrivateAccessVisitor(filename)
    visitor.visit(tree)

    if visitor.violations:
        # print(f"!! {filename} - found violations of private attribute access")
        for lineno, col, name in visitor.violations:
            print(f"!! {filename}:{lineno}:{col} - access to {name}")
        sys.exit(ExitCode.FAILURE)
    else:
        if not quiet:
            print(f"ok {filename}")
        sys.exit(ExitCode.SUCCESS)


if __name__ == "__main__":
    main()
