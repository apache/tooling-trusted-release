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

import contextlib
from typing import TYPE_CHECKING, Any

import htpy

from . import log

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

type Element = htpy.Element
type VoidElement = htpy.VoidElement

a = htpy.a
body = htpy.body
br = htpy.br
button = htpy.button
code = htpy.code
details = htpy.details
div = htpy.div
em = htpy.em
form = htpy.form
h1 = htpy.h1
h2 = htpy.h2
h3 = htpy.h3
html = htpy.html
li = htpy.li
p = htpy.p
pre = htpy.pre
script = htpy.script
span = htpy.span
strong = htpy.strong
summary = htpy.summary
style = htpy.style
table = htpy.table
tbody = htpy.tbody
td = htpy.td
th = htpy.th
thead = htpy.thead
title = htpy.title
tr = htpy.tr
ul = htpy.ul


class BlockElementGetable:
    def __init__(self, block: Block, element: Element):
        self.block = block
        self.element = element

    def __getitem__(self, *items: Element | str | tuple[Element | str, ...]) -> Element:
        element = self.element[*items]
        for i in range(len(self.block.elements) - 1, -1, -1):
            if self.block.elements[i] is self.element:
                self.block.elements[i] = element
                return element
        self.block.append(element)
        return element


class BlockElementCallable:
    def __init__(self, block: Block, constructor: Callable[..., Element]):
        self.block = block
        self.constructor = constructor

    def __call__(self, *args, **kwargs) -> BlockElementGetable:
        element = self.constructor(*args, **kwargs)
        self.block.append(element)
        return BlockElementGetable(self.block, element)

    def __getitem__(self, *items: Any) -> Element:
        element = self.constructor()[*items]
        self.block.append(element)
        return element


class Block:
    __match_args__ = ("elements",)

    def __init__(self, element: Element | None = None, *elements: Element, classes: str | None = None):
        self.element = element
        self.elements: list[Element | str] = list(elements)
        self.classes = classes

    def __str__(self) -> str:
        return f"{self.element}{self.elements}"

    def __repr__(self) -> str:
        return f"{self.element!r}[*{self.elements!r}]"

    def __check_parent(self, child_tag: str, allowed_parent_tags: set[str]) -> None:
        # TODO: We should make this a static check
        tag_name = self.__tag_name()
        if self.element is not None:
            if tag_name not in allowed_parent_tags:
                permitted = ", ".join(allowed_parent_tags) + f", not {tag_name}"
                raise ValueError(f"{child_tag} can only be used as a child of {permitted}")

    def __tag_name(self) -> str:
        if self.element is None:
            return "div"
        return self.element._name

    def append(self, eob: Block | Element) -> None:
        match eob:
            case Block():
                # TODO: Does not support separator
                self.elements.append(eob.collect(depth=2))
            case htpy.Element():
                self.elements.append(eob)

    @contextlib.contextmanager
    def block(
        self,
        element: Element | None = None,
        classes: str | None = None,
        separator: Element | VoidElement | str | None = None,
    ) -> Generator[Block, Any, Any]:
        block = Block(element, classes=classes)
        yield block
        self.append(block.collect(separator=separator))

    def collect(self, separator: Element | VoidElement | str | None = None, depth: int = 1) -> Element:
        src = log.caller_name(depth=depth)

        if separator is not None:
            separated: list[Element | VoidElement | str] = [separator] * (2 * len(self.elements) - 1)
            separated[::2] = self.elements
            elements = separated
        else:
            elements = self.elements

        if self.element is None:
            if self.classes is not None:
                return div(self.classes, data_src=src)[*elements]
            return div(data_src=src)[*elements]

        new_element = self.element.__class__(
            self.element._name,
            self.element._attrs,
            self.element._children,
        )
        if self.classes is not None:
            new_element = new_element(self.classes, data_src=src)
        else:
            new_element = new_element(data_src=src)
        # if self.element._name == "html":
        #     return "<!doctype html>" + new_element[*elements]
        return new_element[*elements]

    @property
    def a(self) -> BlockElementCallable:
        self.__check_parent("a", {"div", "p", "pre"})
        return BlockElementCallable(self, a)

    @property
    def body(self) -> BlockElementCallable:
        self.__check_parent("body", {"html"})
        return BlockElementCallable(self, body)

    @property
    def code(self) -> BlockElementCallable:
        self.__check_parent("code", {"div", "p"})
        return BlockElementCallable(self, code)

    @property
    def details(self) -> BlockElementCallable:
        return BlockElementCallable(self, details)

    @property
    def div(self) -> BlockElementCallable:
        return BlockElementCallable(self, div)

    @property
    def h1(self) -> BlockElementCallable:
        self.__check_parent("h1", {"body", "div"})
        return BlockElementCallable(self, h1)

    @property
    def h2(self) -> BlockElementCallable:
        self.__check_parent("h2", {"body", "div"})
        return BlockElementCallable(self, h2)

    @property
    def h3(self) -> BlockElementCallable:
        self.__check_parent("h3", {"body", "div"})
        return BlockElementCallable(self, h3)

    @property
    def li(self) -> BlockElementCallable:
        self.__check_parent("li", {"ul", "ol"})
        return BlockElementCallable(self, li)

    @property
    def p(self) -> BlockElementCallable:
        self.__check_parent("p", {"body", "div"})
        return BlockElementCallable(self, p)

    @property
    def pre(self) -> BlockElementCallable:
        self.__check_parent("pre", {"body", "div"})
        return BlockElementCallable(self, pre)

    @property
    def span(self) -> BlockElementCallable:
        return BlockElementCallable(self, span)

    @property
    def strong(self) -> BlockElementCallable:
        return BlockElementCallable(self, strong)

    @property
    def style(self) -> BlockElementCallable:
        self.__check_parent("style", {"html", "head"})
        return BlockElementCallable(self, style)

    @property
    def summary(self) -> BlockElementCallable:
        return BlockElementCallable(self, summary)

    @property
    def table(self) -> BlockElementCallable:
        self.__check_parent("table", {"body", "div"})
        return BlockElementCallable(self, table)

    def text(self, text: str) -> None:
        self.elements.append(text)

    @property
    def title(self) -> BlockElementCallable:
        self.__check_parent("title", {"head", "html"})
        return BlockElementCallable(self, title)

    @property
    def tr(self) -> BlockElementCallable:
        self.__check_parent("tr", {"tbody", "table"})
        return BlockElementCallable(self, tr)

    @property
    def ul(self) -> BlockElementCallable:
        self.__check_parent("ul", {"body", "div"})
        return BlockElementCallable(self, ul)


def ul_links(*items: tuple[str, str]) -> Element:
    li_items = [li[a(href=item[0])[item[1]]] for item in items]
    return ul[*li_items]
