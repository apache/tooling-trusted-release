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

import datetime
import pathlib
from collections.abc import Callable, Generator, Iterable, Sequence
from typing import NamedTuple, TypeVar

import atr.db.models as models
import atr.util as util


class Divergence(NamedTuple):
    expected: str
    actual: str


class AnnotatedDivergence(NamedTuple):
    source: str
    validator: str
    components: list[str]
    divergence: Divergence


Divergences = Generator[Divergence]
AnnotatedDivergences = Generator[AnnotatedDivergence]
ReleaseDivergences = Callable[[models.Release], Divergences]
ReleaseAnnotatedDivergences = Callable[[models.Release], AnnotatedDivergences]

T = TypeVar("T")


def divergences[T](expected: T, actual: T) -> Divergences:
    """Compare two values and yield the divergence if they differ."""
    if expected != actual:
        yield Divergence(repr(expected), repr(actual))


def divergences_predicate[T](okay: Callable[[T], bool], expected: str, actual: T) -> Divergences:
    """Apply a predicate to a value and yield the divergence if false."""
    if not okay(actual):
        yield Divergence(expected, repr(actual))


def divergences_with_annotations(
    source: str,
    validator: str,
    components: Sequence[str],
    ds: Divergences,
) -> AnnotatedDivergences:
    """Wrap divergences with a source, validator, and components."""
    for d in ds:
        yield AnnotatedDivergence(source, validator, list(components), d)


def release(r: models.Release) -> AnnotatedDivergences:
    """Check that a release is valid."""
    yield from release_created(r)
    yield from release_name(r)
    yield from release_on_disk(r)
    yield from release_package_managers(r)
    yield from release_released(r)
    yield from release_sboms(r)
    yield from release_vote_logic(r)
    yield from release_votes(r)


def release_components(
    *components: str,
) -> Callable[[ReleaseDivergences], ReleaseAnnotatedDivergences]:
    """Wrap a function that yields divergences to yield annotated divergences."""

    def wrap(original: ReleaseDivergences) -> ReleaseAnnotatedDivergences:
        def replacement(r: models.Release) -> AnnotatedDivergences:
            yield from divergences_with_annotations(
                r.name,
                original.__name__,
                components,
                original(r),
            )

        return replacement

    return wrap


@release_components("Release.created")
def release_created(r: models.Release) -> Divergences:
    """Check that the release created date is in the past."""
    now = datetime.datetime.now(datetime.UTC)

    def predicate(dt: datetime.datetime) -> bool:
        return dt < now

    expected = "value to be in the past"
    yield from divergences_predicate(predicate, expected, r.created)


@release_components("Release.name")
def release_name(r: models.Release) -> Divergences:
    """Check that the release name is valid."""
    expected = models.release_name(r.project_name, r.version)
    actual = r.name
    yield from divergences(expected, actual)


@release_components()
def release_on_disk(r: models.Release) -> Divergences:
    """Check that the release is on disk."""
    path = util.release_directory(r)

    def okay(p: pathlib.Path) -> bool:
        # The release directory must exist and contain at least one entry
        return p.exists() and any(p.iterdir())

    expected = "directory to exist and contain files"
    yield from divergences_predicate(okay, expected, path)


@release_components("Release.package_managers")
def release_package_managers(r: models.Release) -> Divergences:
    """Check that the release package managers are empty."""
    expected = []
    actual = r.package_managers
    yield from divergences(expected, actual)


@release_components("Release.released")
def release_released(r: models.Release) -> Divergences:
    """Check that the release released date is in the past or None."""
    now = datetime.datetime.now(datetime.UTC)

    def okay(dt: datetime.datetime | None) -> bool:
        if dt is None:
            return True
        return dt < now

    expected = "value to be in the past or None"
    yield from divergences_predicate(okay, expected, r.released)


@release_components("Release.sboms")
def release_sboms(r: models.Release) -> Divergences:
    """Check that the release sboms are empty."""
    expected = []
    actual = r.sboms
    yield from divergences(expected, actual)


@release_components("Release.vote_started", "Release.vote_resolved")
def release_vote_logic(r: models.Release) -> Divergences:
    """Check that the release vote logic is valid."""

    def okay(sr: tuple[datetime.datetime | None, datetime.datetime | None]) -> bool:
        # The vote_resolved property must not be set unless vote_started is set
        match sr:
            case (None, None) | (_, None) | (_, _):
                return True
            case (None, _):
                return False

    expected = "vote_started to be set when vote_resolved is set"
    actual = (r.vote_started, r.vote_resolved)
    yield from divergences_predicate(okay, expected, actual)


@release_components("Release.votes")
def release_votes(r: models.Release) -> Divergences:
    """Check that the release votes are empty."""
    expected = []
    actual = r.votes
    yield from divergences(expected, actual)


def releases(rs: Iterable[models.Release]) -> AnnotatedDivergences:
    """Check that the releases are valid."""
    for r in rs:
        yield from release(r)
