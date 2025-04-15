#!/usr/bin/env python3

import ast
import enum
import pathlib
import sys
from collections.abc import Sequence


class ExitCode(enum.IntEnum):
    SUCCESS = 0
    FAILURE = 1
    USAGE_ERROR = 2


def _extract_top_level_function_names(tree: ast.Module) -> list[str]:
    function_names: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.AsyncFunctionDef) or isinstance(node, ast.FunctionDef):
            function_names.append(_toggle_sortability(node.name))
    return function_names


def _extract_top_level_class_names(tree: ast.Module) -> list[str]:
    class_names: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            class_names.append(node.name)
    return class_names


def _parse_python_code(code: str, filename: str) -> ast.Module | None:
    try:
        return ast.parse(code, filename=filename)
    except SyntaxError as e:
        print(f"Error: Invalid Python syntax in {filename}: {e}", file=sys.stderr)
        return None


def _read_file_content(file_path: pathlib.Path) -> str | None:
    try:
        return file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"Error: Could not read file {file_path}: {e}", file=sys.stderr)
        return None


def _toggle_sortability(name: str) -> str:
    if name.startswith("_"):
        return name[1:]
    else:
        return "_" + name


def _verify_names_are_sorted(names: Sequence[str], filename: str, interface_type: str) -> bool:
    is_sorted = all(names[i] <= names[i + 1] for i in range(len(names) - 1))
    if is_sorted:
        return True

    for i in range(len(names) - 1):
        if names[i] > names[i + 1]:
            if interface_type == "class":
                a = names[i]
                b = names[i + 1]
            else:
                a = _toggle_sortability(names[i])
                b = _toggle_sortability(names[i + 1])
            print(
                f"!! {filename} - {interface_type} '{b}' is misordered relative to '{a}'",
                file=sys.stderr,
            )
    return False


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python interface_order.py <filename>", file=sys.stderr)
        sys.exit(ExitCode.USAGE_ERROR)

    file_path = pathlib.Path(sys.argv[1])

    content = _read_file_content(file_path)
    if content is None:
        sys.exit(ExitCode.FAILURE)

    tree = _parse_python_code(content, str(file_path))
    if tree is None:
        sys.exit(ExitCode.FAILURE)

    class_names = _extract_top_level_class_names(tree)
    function_names = _extract_top_level_function_names(tree)

    all_ok = True
    if not _verify_names_are_sorted(function_names, str(file_path), "function"):
        all_ok = False

    for class_name in class_names:
        if class_name.startswith("_"):
            print(f"!! {file_path} - class '{class_name}' is private", file=sys.stderr)
            all_ok = False

    if not _verify_names_are_sorted(class_names, str(file_path), "class"):
        all_ok = False

    if all_ok:
        print(f"ok {file_path}")
        sys.exit(ExitCode.SUCCESS)
    else:
        sys.exit(ExitCode.FAILURE)


if __name__ == "__main__":
    main()
