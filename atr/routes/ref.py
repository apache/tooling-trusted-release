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

import ast
import pathlib

import quart
import werkzeug.wrappers.response as response

import atr.config as config
import atr.route as route

# Perhaps GitHub will get around to implementing symbol permalinks:
# https://github.com/orgs/community/discussions/13292
# Then this code will be easier, but we should still keep our own links


@route.public("/ref/<path:ref_path>")
async def resolve(session: route.CommitterSession | None, ref_path: str) -> response.Response:
    if ":" not in ref_path:
        quart.abort(404)

    file_path_str, symbol = ref_path.rsplit(":", 1)

    project_root = pathlib.Path(config.get().PROJECT_ROOT)
    file_path = project_root / file_path_str

    try:
        resolved_file = file_path.resolve()
        resolved_file.relative_to(project_root)
    except (FileNotFoundError, ValueError):
        quart.abort(404)

    if not resolved_file.exists() or not resolved_file.is_file():
        quart.abort(404)

    line_number = await _resolve_symbol_to_line(resolved_file, symbol)

    if line_number is None:
        quart.abort(404)

    github_url = f"https://github.com/apache/tooling-trusted-releases/blob/main/{file_path_str}#L{line_number}"

    return quart.redirect(github_url, code=303)


async def _resolve_symbol_to_line(file_path: pathlib.Path, symbol: str) -> int | None:
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))
    except Exception:
        return None

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == symbol:
                return node.lineno
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == symbol:
                    return node.lineno
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == symbol:
                return node.lineno

    return None
