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

import asyncio
import datetime
import pathlib
from collections.abc import AsyncGenerator, Callable, Generator, Iterable, Sequence
from typing import NamedTuple, TypeVar

import atr.db as db
import atr.models.sql as sql
import atr.util as util


class Divergence(NamedTuple):
    expected: str
    actual: str


class AnnotatedDivergence(NamedTuple):
    components: list[str]
    validator: str
    source: str
    divergence: Divergence


Divergences = Generator[Divergence]
AnnotatedDivergences = Generator[AnnotatedDivergence]
AsyncAnnotatedDivergences = AsyncGenerator[AnnotatedDivergence]
CommitteeDivergences = Callable[[sql.Committee], Divergences]
CommitteeAnnotatedDivergences = Callable[[sql.Committee], AnnotatedDivergences]
ProjectDivergences = Callable[[sql.Project], Divergences]
ProjectAnnotatedDivergences = Callable[[sql.Project], AnnotatedDivergences]
ReleaseDivergences = Callable[[sql.Release], Divergences]
ReleaseAnnotatedDivergences = Callable[[sql.Release], AnnotatedDivergences]

T = TypeVar("T")


def committee(c: sql.Committee) -> AnnotatedDivergences:
    """Check that a committee is valid."""

    yield from committee_child_committees(c)
    yield from committee_full_name(c)


def committee_components(
    *components: str,
) -> Callable[[CommitteeDivergences], CommitteeAnnotatedDivergences]:
    """Wrap a Committee divergence generator to yield annotated divergences."""

    def wrap(original: CommitteeDivergences) -> CommitteeAnnotatedDivergences:
        def replacement(c: sql.Committee) -> AnnotatedDivergences:
            yield from divergences_with_annotations(
                components,
                original.__name__,
                c.name,
                original(c),
            )

        return replacement

    return wrap


@committee_components("Committee.full_name")
def committee_full_name(c: sql.Committee) -> Divergences:
    """Validate the Committee.full_name value."""

    full_name = c.full_name

    def present(fn: str | None) -> bool:
        return bool(fn)

    yield from divergences_predicate(
        present,
        "value to be set",
        full_name,
    )

    def trimmed(fn: str | None) -> bool:
        return False if fn is None else (fn == fn.strip())

    yield from divergences_predicate(
        trimmed,
        "value not to have surrounding whitespace",
        full_name,
    )

    def not_prefixed(fn: str | None) -> bool:
        return False if fn is None else (not fn.startswith("Apache "))

    yield from divergences_predicate(
        not_prefixed,
        "value not to start with 'Apache '",
        full_name,
    )


@committee_components("Committee.child_committees")
def committee_child_committees(c: sql.Committee) -> Divergences:
    """Check that a committee has no child_committees."""

    expected: list[object] = []
    actual = c.child_committees
    yield from divergences(expected, actual)


def committees(cs: Iterable[sql.Committee]) -> AnnotatedDivergences:
    """Validate multiple committees."""
    for c in cs:
        yield from committee(c)


def divergences[T](expected: T, actual: T) -> Divergences:
    """Compare two values and yield the divergence if they differ."""
    if expected != actual:
        yield Divergence(repr(expected), repr(actual))


def divergences_predicate[T](okay: Callable[[T], bool], expected: str, actual: T) -> Divergences:
    """Apply a predicate to a value and yield the divergence if false."""
    if not okay(actual):
        yield Divergence(expected, repr(actual))


def divergences_with_annotations(
    components: Sequence[str],
    validator: str,
    source: str,
    ds: Divergences,
) -> AnnotatedDivergences:
    """Wrap divergences with components, validator, and source."""
    for d in ds:
        yield AnnotatedDivergence(list(components), validator, source, d)


async def everything(data: db.Session) -> AsyncAnnotatedDivergences:
    """Yield divergences for all projects and releases in the DB."""
    committees_sorted = await data.committee(_child_committees=True).order_by(sql.Committee.name).all()
    projects_sorted = await data.project(_distribution_channels=True).order_by(sql.Project.name).all()
    releases_sorted = await data.release().order_by(sql.Release.name).all()

    for c in await asyncio.to_thread(committees, committees_sorted):
        yield c

    for p in await asyncio.to_thread(projects, projects_sorted):
        yield p

    for r in await asyncio.to_thread(releases, releases_sorted):
        yield r


def project(p: sql.Project) -> AnnotatedDivergences:
    """Check that a project is valid."""

    yield from project_category(p)
    yield from project_committee(p)
    yield from project_created(p)
    yield from project_distribution_channels(p)
    yield from project_full_name(p)
    yield from project_programming_languages(p)
    yield from project_release_policy(p)


def project_components(
    *components: str,
) -> Callable[[ProjectDivergences], ProjectAnnotatedDivergences]:
    """Wrap a Project divergence generator to yield annotated divergences."""

    def wrap(original: ProjectDivergences) -> ProjectAnnotatedDivergences:
        def replacement(p: sql.Project) -> AnnotatedDivergences:
            yield from divergences_with_annotations(
                components,
                original.__name__,
                p.name,
                original(p),
            )

        return replacement

    return wrap


@project_components("Project.category")
def project_category(p: sql.Project) -> Divergences:
    """Check that the category string uses 'label, label' syntax without colons."""

    def okay(cat: str | None) -> bool:
        if not cat:
            return True
        tokens = [t.strip() for t in cat.split(",")]
        if any((not t) or (":" in t) for t in tokens):
            return False
        return True

    expected = "comma separated labels without colon"
    yield from divergences_predicate(okay, expected, p.category)


@project_components("Project.committee_name")
def project_committee(p: sql.Project) -> Divergences:
    """Check that the project is linked to a committee."""

    def okay(cn: str | None) -> bool:
        return cn is not None

    expected = "committee_name to be set"
    yield from divergences_predicate(okay, expected, p.committee_name)


@project_components("Project.created")
def project_created(p: sql.Project) -> Divergences:
    """Check that the project created timestamp is in the past."""
    now = datetime.datetime.now(datetime.UTC)

    def predicate(dt: datetime.datetime) -> bool:
        return dt < now

    expected = "value to be in the past"
    yield from divergences_predicate(predicate, expected, p.created)


@project_components("Project.distribution_channels")
def project_distribution_channels(p: sql.Project) -> Divergences:
    """Check that distribution_channels is empty."""
    expected: list[object] = []
    actual = p.distribution_channels
    yield from divergences(expected, actual)


@project_components("Project.full_name")
def project_full_name(p: sql.Project) -> Divergences:
    """Check that the project full_name is present and starts with 'Apache '."""

    def okay(fn: str | None) -> bool:
        return (fn is not None) and fn.startswith("Apache ")

    expected = "full_name to be set and start with 'Apache '"
    yield from divergences_predicate(okay, expected, p.full_name)


@project_components("Project.programming_languages")
def project_programming_languages(p: sql.Project) -> Divergences:
    """Check that programming_languages uses 'label, label' syntax without colons."""

    def okay(pl: str | None) -> bool:
        if not pl:
            return True
        tokens = [t.strip() for t in pl.split(",")]
        if any((not t) or (":" in t) for t in tokens):
            return False
        return True

    expected = "comma separated labels without colon"
    yield from divergences_predicate(okay, expected, p.programming_languages)


@project_components("Project.release_policy")
def project_release_policy(p: sql.Project) -> Divergences:
    """Ensure that release_policy is None."""

    expected = None
    actual = p.release_policy_id
    yield from divergences(expected, actual)


def projects(ps: Iterable[sql.Project]) -> AnnotatedDivergences:
    """Validate multiple projects."""
    for p in ps:
        yield from project(p)


def release(r: sql.Release) -> AnnotatedDivergences:
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
        def replacement(r: sql.Release) -> AnnotatedDivergences:
            yield from divergences_with_annotations(
                components,
                original.__name__,
                r.name,
                original(r),
            )

        return replacement

    return wrap


@release_components("Release.created")
def release_created(r: sql.Release) -> Divergences:
    """Check that the release created date is in the past."""
    now = datetime.datetime.now(datetime.UTC)

    def predicate(dt: datetime.datetime) -> bool:
        return dt < now

    expected = "value to be in the past"
    yield from divergences_predicate(predicate, expected, r.created)


@release_components("Release.name")
def release_name(r: sql.Release) -> Divergences:
    """Check that the release name is valid."""
    expected = sql.release_name(r.project_name, r.version)
    actual = r.name
    yield from divergences(expected, actual)


@release_components("Release")
def release_on_disk(r: sql.Release) -> Divergences:
    """Check that the release is on disk."""
    path = util.release_directory(r)

    def okay(p: pathlib.Path) -> bool:
        # The release directory must exist and contain at least one entry
        return p.exists() and any(p.iterdir())

    expected = "directory to exist and contain files"
    yield from divergences_predicate(okay, expected, path)


@release_components("Release.package_managers")
def release_package_managers(r: sql.Release) -> Divergences:
    """Check that the release package managers are empty."""
    expected = []
    actual = r.package_managers
    yield from divergences(expected, actual)


@release_components("Release.released")
def release_released(r: sql.Release) -> Divergences:
    """Check that the release released date is in the past or None."""
    now = datetime.datetime.now(datetime.UTC)

    def okay(dt: datetime.datetime | None) -> bool:
        if dt is None:
            return True
        return dt < now

    expected = "value to be in the past or None"
    yield from divergences_predicate(okay, expected, r.released)


@release_components("Release.sboms")
def release_sboms(r: sql.Release) -> Divergences:
    """Check that the release sboms are empty."""
    expected = []
    actual = r.sboms
    yield from divergences(expected, actual)


@release_components("Release.vote_started", "Release.vote_resolved")
def release_vote_logic(r: sql.Release) -> Divergences:
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
def release_votes(r: sql.Release) -> Divergences:
    """Check that the release votes are empty."""
    expected = []
    actual = r.votes
    yield from divergences(expected, actual)


def releases(rs: Iterable[sql.Release]) -> AnnotatedDivergences:
    """Check that the releases are valid."""
    for r in rs:
        yield from release(r)
