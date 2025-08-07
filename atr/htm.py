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

from typing import TYPE_CHECKING, Any

import htpy

if TYPE_CHECKING:
    from collections.abc import Callable


class BlockElementGetable:
    def __init__(self, block: Block, element: htpy.Element):
        self.block = block
        self.element = element

    def __getitem__(self, *items: htpy.Element | str) -> htpy.Element:
        element = self.element[*items]
        for i in range(len(self.block.elements) - 1, -1, -1):
            if self.block.elements[i] is self.element:
                self.block.elements[i] = element
                return element
        self.block.append(element)
        return element


class BlockElementCallable:
    def __init__(self, block: Block, constructor: Callable[..., htpy.Element]):
        self.block = block
        self.constructor = constructor

    def __call__(self, *args, **kwargs) -> BlockElementGetable:
        element = self.constructor(*args, **kwargs)
        self.block.append(element)
        return BlockElementGetable(self.block, element)

    def __getitem__(self, *items: Any) -> htpy.Element:
        element = self.constructor()[*items]
        self.block.append(element)
        return element


class Block:
    def __init__(self, element: htpy.Element | None = None, *elements: htpy.Element):
        self.element = element
        self.elements: list[htpy.Element | str] = list(elements)

    def __str__(self) -> str:
        return f"{self.element}{self.elements}"

    def __repr__(self) -> str:
        return f"{self.element!r}[*{self.elements!r}]"

    def append(self, element: htpy.Element) -> None:
        self.elements.append(element)

    def collect(self, separator: str | None = None) -> htpy.Element:
        if separator is not None:
            separated: list[htpy.Element | str] = [separator] * (2 * len(self.elements) - 1)
            separated[::2] = self.elements
            self.elements = separated
        if self.element is None:
            return htpy.div[*self.elements]
        return self.element[*self.elements]

    @property
    def a(self) -> BlockElementCallable:
        return BlockElementCallable(self, htpy.a)

    @property
    def code(self) -> BlockElementCallable:
        return BlockElementCallable(self, htpy.code)

    @property
    def details(self) -> BlockElementCallable:
        return BlockElementCallable(self, htpy.details)

    @property
    def div(self) -> BlockElementCallable:
        return BlockElementCallable(self, htpy.div)

    @property
    def h1(self) -> BlockElementCallable:
        return BlockElementCallable(self, htpy.h1)

    @property
    def h2(self) -> BlockElementCallable:
        return BlockElementCallable(self, htpy.h2)

    @property
    def h3(self) -> BlockElementCallable:
        return BlockElementCallable(self, htpy.h3)

    @property
    def p(self) -> BlockElementCallable:
        return BlockElementCallable(self, htpy.p)

    @property
    def pre(self) -> BlockElementCallable:
        return BlockElementCallable(self, htpy.pre)

    @property
    def span(self) -> BlockElementCallable:
        return BlockElementCallable(self, htpy.span)

    @property
    def strong(self) -> BlockElementCallable:
        return BlockElementCallable(self, htpy.strong)

    @property
    def summary(self) -> BlockElementCallable:
        return BlockElementCallable(self, htpy.summary)

    @property
    def table(self) -> BlockElementCallable:
        return BlockElementCallable(self, htpy.table)

    def text(self, text: str) -> None:
        self.elements.append(text)
