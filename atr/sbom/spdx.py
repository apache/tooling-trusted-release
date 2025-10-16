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

from __future__ import annotations

from . import constants


class LicenseExpressionParser:
    def __init__(self, items: list[tuple[str, str]], text: str) -> None:
        self.items = items
        self.text = text
        self.position = 0

    def parse(self) -> set[str]:
        atoms, _ = self.parse_expression()
        if self.position != len(self.items):
            raise ValueError(self.text)
        return atoms

    def parse_conjunction(self) -> tuple[set[str], bool]:
        atoms, simple = self.parse_with()
        while self.peek("AND"):
            self.position += 1
            atoms |= self.parse_with()[0]
            simple = False
        return atoms, simple

    def parse_expression(self) -> tuple[set[str], bool]:
        atoms, simple = self.parse_conjunction()
        while self.peek("OR"):
            self.position += 1
            atoms |= self.parse_conjunction()[0]
            simple = False
        return atoms, simple

    def parse_primary(self, for_addition: bool) -> tuple[set[str], bool]:
        if self.position >= len(self.items):
            raise ValueError(self.text)
        kind, value = self.items[self.position]
        if kind == "LPAREN":
            self.position += 1
            atoms, _ = self.parse_expression()
            if not self.peek("RPAREN"):
                raise ValueError(self.text)
            self.position += 1
            return atoms, False
        if (not for_addition) and (kind in {"ID", "LICREF", "DOCREF"}):
            self.position += 1
            base = value
            if self.peek("PLUS"):
                self.position += 1
            return {base}, True
        if for_addition and (kind in {"ID", "LICREF", "DOCREF", "ADDREF"}):
            self.position += 1
            return set(), True
        raise ValueError(self.text)

    def parse_with(self) -> tuple[set[str], bool]:
        atoms, simple = self.parse_primary(False)
        while self.peek("WITH"):
            if not simple:
                raise ValueError(self.text)
            self.position += 1
            _, right_simple = self.parse_primary(True)
            if not right_simple:
                raise ValueError(self.text)
            simple = False
        return atoms, simple

    def peek(self, kind: str) -> bool:
        return (self.position < len(self.items)) and (self.items[self.position][0] == kind)


def license_expression_atoms(expr: str) -> set[str]:
    pos = 0
    tokens: list[tuple[str, str]] = []
    for match in constants.spdx.TOKEN.finditer(expr):
        if match.start() != pos:
            raise ValueError(expr)
        pos = match.end()
        kind = match.lastgroup
        if (kind) and (kind != "WS"):
            tokens.append((kind, match.group(kind)))
    if pos != len(expr):
        raise ValueError(expr)

    return LicenseExpressionParser(tokens, expr).parse()
