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

import dataclasses
import os
import pathlib
import re
import signal
import sys
from typing import Final

ARTIFACT_SUFFIXES: Final[list[str]] = [
    "bin",
    "crate",
    "deb",
    "dmg",
    "exe",
    "far",
    "gem",
    "jar.pack.gz",
    "jar",
    "msi",
    "nar",
    "nbm",
    "snupkg",
    "nupkg",
    "pkg",
    "pom",
    "rar",
    "rpm",
    "sh",
    "slingosgifeature",
    "taco",
    "tar.bz2",
    "tar.gz",
    "tar.xz",
    "tar",
    "tgz",
    "vsix",
    "war",
    "whl",
    "zip",
]

# "mds" is used in ozone
# "SHA256" and "SHA512" are used in ranger
# "MD5" is used in samza
# "asc.asc" is used in felix
METADATA_SUFFIXES: Final[list[str]] = [
    "asc.asc",
    "asc.md5",
    "asc.sha1",
    "asc.sha256",
    "asc.sha512",
    "cdx.json",
    "cdx.xml",
    "sha512.asc",
    "sha512.md5",
    "sha512.sha1",
    "sha512.sha512",
    "asc",
    "MD5",
    "md5",
    "mds",
    "prov",
    "sh1",
    "sha1",
    "sha256",
    "SHA256",
    "SHA512",
    "sha512sum",
    "sha512",
    "sha",
    "sig",
]

# .license is used in high volume in netbeans
SKIPPABLE_SUFFIXES: Final[list[str]] = [
    ".bak",
    ".css",
    ".gif",
    ".html",
    ".json",
    ".license",
    ".md",
    ".pdf",
    ".png",
    ".temp",
    ".tmp",
    ".txt",
    ".xml",
    ".yaml",
]

# Should perhaps not include javadoc
# app
# doc
# docs
# example
# markdown
# nodeps
# release
# sdk
# tests
VARIANT_PATTERNS: Final[list[str]] = [
    "binary-assembly",
    "binary",
    "bin",
    "dist",
    "install_[a-z][a-z](?:-[A-Z][A-Z])?",
    "javadoc",
    "langpack_[a-z][a-z](?:-[A-Z][A-Z])?",
    "lib-debug",
    "lib",
    "pkg",
    "source-release",
    "sources",
    "source",
    "src",
]

_CANDIDATE_TAG: Final = r"(?: Candidate | candidate | RC | Rc | rc ) [.-]? [0-9]+"
_CANDIDATE_PARTIAL: Final = re.compile(rf"(?x) - {_CANDIDATE_TAG}")
_CANDIDATE_WHOLE: Final = re.compile(rf"(?x) ^ {_CANDIDATE_TAG} $")


@dataclasses.dataclass
class Analysis:
    versions: dict[str, set[str]]
    subs: dict[str, set[str]]
    templates: dict[str, dict[str, int]]


def architecture_pattern() -> str:
    architectures = [
        "cp[0-9]+-cp[0-9]+m?-[a-z0-9_]+(?:[.]manylinux[a-z0-9_]+)*",
        "pp[0-9]+-pypy[0-9]+_pp[0-9]+-[a-z0-9_]+(?:[.]manylinux[a-z0-9_]+)?",
        "darwin(?:-unknown)?-(?:aarch64|amd64|arm64|64bit|arm64bit|x64)",
        "Linux-CentOS[0-9]+",
        "Linux-Ubuntu[0-9]+",
        "linux(?:-glibc|musl|unknown)?-(?:aarch64|amd64|arm64|64bit|arm64bit|x64)",
        "linux.gtk.x86_64",
        "mac(?:os|OS)?(?:-unknown)?-(?:aarch64|amd64|arm64|64bit|arm64bit|x64)",
        "macos.cocoa.x86_64",
        "osx(?:-unknown)?-(?:aarch64|amd64|arm64|64bit|arm64bit|x64)",
        "py2.py3-none-any",
        "py3-none-any",
        "win32.win32.x86_64",
        "windows(?:-unknown)?-(?:aarch64|amd64|arm64|64bit|arm64bit|x64)",
        "x86_64(?:-noavx2)?",
        "(?:x64|x86)-windows-staticaarch64",
        "amd64",
        "arm",
        "Darwin",
        "Linux_x86",
        "linux",
        "MacOS_x86-64",
        "macosx?",
        "noarch",
        "Win_x86",
        "win(?:dows)?",
    ]
    return "(" + "|".join(architectures) + ")(?=[_.-])"


def candidate_match(segment: str) -> re.Match[str] | None:
    return _CANDIDATE_WHOLE.match(segment) or _CANDIDATE_PARTIAL.search(segment)


def candidate_removed(path: pathlib.Path) -> pathlib.Path:
    parts = []
    for part in path.parts:
        if _CANDIDATE_WHOLE.match(part):
            continue
        if part := _CANDIDATE_PARTIAL.sub("", part):
            parts.append(part)
    return pathlib.Path(*parts)


def component_parse(i: int, component: str, size: int, elements: dict[str, str | None]) -> None:
    if i == 0:
        # CORE
        # Never starts with "apache-"
        elements["core"] = component
    elif (i == 1) and (size == 2):
        elements["template"] = filename_parse(component, elements)[0]
    elif i == 1:
        # SUB or VERSION
        # TODO: Check total depth to give an indication of SUB?
        if is_version(component):
            elements["version"] = version_parse(component, elements)
        else:
            elements["sub"] = component
    elif (i == 2) and (size == 3):
        # CORE/VERSION/FILENAME
        elements["template"] = filename_parse(component, elements)[0]
    elif (i == 2) and (size == 4):
        # VERSION
        elements["version"] = version_parse(component, elements)
    elif (i == 3) and (size == 4):
        # CORE/VERSION/SUB/FILENAME
        elements["template"] = filename_parse(component, elements)[0]
    elif i == (size - 1):
        # FILENAME, but more deeply nested
        elements["template"] = filename_parse(component, elements)[0]
        # elements["missing"] += 1


def elements_update(elements: dict[str, str | None], core: str, analysis: Analysis) -> None:
    if core not in analysis.versions:
        analysis.versions[core] = set()
    if core not in analysis.subs:
        analysis.subs[core] = set()
    if core not in analysis.templates:
        analysis.templates[core] = {}

    if elements["version"] is not None:
        analysis.versions[core].add(elements["version"])
    if elements["sub"] is not None:
        analysis.subs[core].add(elements["sub"])
    if elements["template"] is not None:
        if elements["template"] not in analysis.templates[core]:
            analysis.templates[core][elements["template"]] = 0
        analysis.templates[core][elements["template"]] += 1


def extension_pattern() -> str:
    # https://tableau.github.io/connector-plugin-sdk/docs/
    # https://en.wikipedia.org/wiki/WAR_(file_format)
    # https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=vs-2022
    # What's the status of "pom"?
    # We've included "sh", so perhaps we should include "patch"
    metadata_artifact_pattern = (
        r"(?P<metadata_artifact>" + "|".join(["[.]" + re.escape(a) for a in ARTIFACT_SUFFIXES]) + r")"
    )
    metadata_pattern = r"(?P<metadata>" + "|".join(["[.]" + re.escape(m) for m in METADATA_SUFFIXES]) + r")"
    artifact_pattern = r"(?P<artifact>" + "|".join(["[.]" + re.escape(a) for a in ARTIFACT_SUFFIXES]) + r")"

    pattern = rf"((?:{metadata_artifact_pattern}{metadata_pattern})|{artifact_pattern})$"
    return pattern


def filename_parse(filename: str, elements: dict[str, str | None]) -> tuple[str, dict[str, list[str]]]:
    substitutions: dict[str, list[str]] = {
        "sub": [],
        "core": [],
        "version": [],
        "variant": [],
        "tag": [],
        "arch": [],
        "ext": [],
        "label": [],
    }

    def sub(pattern: str, name: str, replacement: str, filename: str) -> str:
        matches = re.findall(pattern, filename)
        if matches:
            substitutions[name] = matches if isinstance(matches[0], str) else [m[0] for m in matches]
        else:
            substitutions[name] = []
        return re.sub(pattern, replacement, filename)

    filename = sub(r"apache(?=[_.-])", "core", "α", filename)
    # TODO: -incubating
    # There is no standard position for -incubating
    if elements["sub"]:
        # Replace SUB before CORE because CORE may contain SUB
        filename = sub(elements["sub"] + r"(?=[_.-])", "sub", "σ", filename)
    if elements["core"]:
        filename = sub(elements["core"] + r"(?=[_.-])", "core", "κ", filename)
    if elements["version"]:
        filename = sub(elements["version"] + r"(?=[_.-])", "version", "β", filename)
    filename = sub(variant_pattern(), "variant", "ρ", filename)
    filename = sub(r"[0-9]+[.][0-9]+(?:[.][0-9]+(?:[.][0-9]+)?)?(?=[_.-])", "tag", "τ", filename)
    filename = sub(architecture_pattern(), "arch", "ι", filename)
    filename = sub(extension_pattern(), "ext", ".ε", filename)
    if "LABEL_MODE" in os.environ:
        filename = sub(r"(?<=-)[a-z]+[0-9]*(?:-[a-z]+[0-9]*)*(?=-)", "label", "λ", filename)

    filename = filename.replace("α", "ASF")
    filename = filename.replace("σ", "SUB")
    filename = filename.replace("β", "VERSION")
    filename = filename.replace("κ", "CORE")
    filename = filename.replace("ρ", "VARIANT")
    filename = filename.replace("τ", "TAG")
    filename = filename.replace("ι", "ARCH")
    filename = filename.replace("ε", "EXT")
    if "LABEL_MODE" in os.environ:
        filename = filename.replace("λ", "LABEL")
    return filename, substitutions


def is_artifact(file_path: str | pathlib.Path) -> bool:
    """Check whether a file path represents a release artifact based on its extension."""
    filename = str(file_path)
    search = re.search(extension_pattern(), filename)
    return bool(search and search.group("artifact"))


def is_candidate(path: pathlib.Path) -> bool:
    return any(is_candidate_segment(part) for part in path.parts)


def is_candidate_segment(segment: str) -> bool:
    return bool(candidate_match(segment))


def is_skippable(path: pathlib.Path) -> bool:
    if len(path.parts) < 2:
        return True
    if path.parts[0] == "META":
        return True
    # "KEYS", "LICENSE", "NOTICE", "README"...
    if "." not in path.name:
        return True
    if path.name in {".htaccess"}:
        return True
    for suffix in SKIPPABLE_SUFFIXES:
        if suffix in path.suffixes:
            return True
    return False


def is_version(component: str) -> bool:
    return component[:1].isdigit() or ("." in component)


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} FILENAME")
        sys.exit(1)

    filename = sys.argv[1]

    path_lines = []
    with open(filename) as f:
        for line in f:
            path_lines.append(line.strip())
    return perform_and_print(path_lines)


def perform(path_lines: list[str]) -> Analysis:
    """Perform the analysis."""
    paths = []
    for line in path_lines:
        path = pathlib.Path(line.strip())
        if is_skippable(path):
            continue
        paths.append(path)

    analysis = Analysis(
        versions={},
        subs={},
        templates={},
    )
    for path in paths:
        size = len(path.parts)
        elements: dict[str, str | None] = {
            "core": None,
            "version": None,
            "sub": None,
            "template": None,
            "substitutions": None,
        }
        for i, component in enumerate(path.parts):
            component_parse(i, component, size, elements)

        if elements["core"] is not None:
            elements_update(elements, elements["core"], analysis)

    return analysis


def perform_and_print(path_lines: list[str]) -> None:
    """Perform the analysis and print the results."""
    analysis = perform(path_lines)
    # Prevent BrokenPipeError when piping output to other commands
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    try:
        print_data(analysis)
    except BrokenPipeError:
        ...


def print_data(analysis: Analysis) -> None:
    # Print the templates of all projects
    for core, version_set in sorted(analysis.versions.items()):
        print("---", core, "---")
        print()
        if version_set:
            print("  VERSIONS:", ", ".join(sorted(version_set)))
        if analysis.subs[core]:
            print("  SUBS:", ", ".join(sorted(analysis.subs[core])))
        print()
        for template, count in sorted(analysis.templates[core].items()):
            print(f"  {count:3d} {template}")
        print()
        print()
    sys.stdout.flush()


def substitutions_format(substitutions: dict[str, list[str]]) -> str:
    subs = []
    for key, values in substitutions.items():
        if values:
            subs.append(f"{key.upper()}: {', '.join(values)}")
    return ", ".join(subs)


def variant_pattern() -> str:
    # .bin can also be an EXT
    # For example in opennlp
    # Which is why we do (?<=[_-])
    return "(?<=[_-])(" + "|".join(VARIANT_PATTERNS) + ")(?=[_.-])"


def version_parse(version: str, elements: dict[str, str | None]) -> str:
    if elements["core"] is None:
        return version
    if version.startswith(elements["core"] + "-"):
        return version[len(elements["core"]) + 1 :]
    return version


if __name__ == "__main__":
    main()
