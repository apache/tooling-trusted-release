#!/usr/bin/env python3

import os
import pathlib
import re
import signal
import sys


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


def component_parse(i: int, component: str, size: int, elements: dict[str, str | None]) -> None:
    if i == 0:
        # CORE
        # Never starts with "apache-"
        elements["core"] = component
    elif (i == 1) and (size == 2):
        elements["template"] = filename_parse(component, elements)
    elif i == 1:
        # SUB or VERSION
        # TODO: Check total depth to give an indication of SUB?
        if is_version(component):
            elements["version"] = version_parse(component, elements)
        else:
            elements["sub"] = component
    elif (i == 2) and (size == 3):
        # CORE/VERSION/FILENAME
        elements["template"] = filename_parse(component, elements)
    elif (i == 2) and (size == 4):
        # VERSION
        elements["version"] = version_parse(component, elements)
    elif (i == 3) and (size == 4):
        # CORE/VERSION/SUB/FILENAME
        elements["template"] = filename_parse(component, elements)
    elif i == (size - 1):
        # FILENAME, but more deeply nested
        elements["template"] = filename_parse(component, elements)
        # elements["missing"] += 1


def extension_pattern() -> str:
    # https://tableau.github.io/connector-plugin-sdk/docs/
    # https://en.wikipedia.org/wiki/WAR_(file_format)
    # https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=vs-2022
    # What's the status of "pom"?
    # We've included "sh", so perhaps we should include "patch"
    archives = [
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
    metadata = [
        "asc.asc",
        "asc.md5",
        "asc.sha1",
        "asc.sha256",
        "asc.sha512",
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
    patterns = []
    for archive in archives:
        for metadatum in metadata:
            patterns.append(f"[.]{archive}[.]{metadatum}")
        # This must come after the metadata patterns
        patterns.append(f"[.]{archive}")
    return "(" + "|".join(patterns) + ")$"


def filename_parse(filename: str, elements: dict[str, str | None]) -> str:
    filename = re.sub(r"apache(?=[_.-])", "α", filename)
    # TODO: -incubating
    # There is no standard position for -incubating
    if elements["sub"]:
        # Replace SUB before CORE because CORE may contain SUB
        filename = re.sub(elements["sub"] + r"(?=[_.-])", "σ", filename)
    if elements["core"]:
        filename = re.sub(elements["core"] + r"(?=[_.-])", "κ", filename)
    if elements["version"]:
        filename = re.sub(elements["version"] + r"(?=[_.-])", "β", filename)
    filename = re.sub(variant_pattern(), "ρ", filename)
    filename = re.sub(r"[0-9]+[.][0-9]+(?:[.][0-9]+(?:[.][0-9]+)?)?(?=[_.-])", "τ", filename)
    filename = re.sub(architecture_pattern(), "ι", filename)
    filename = re.sub(extension_pattern(), ".ε", filename)
    if "LABEL_MODE" in os.environ:
        filename = re.sub(r"(?<=-)[a-z]+[0-9]*(?:-[a-z]+[0-9]*)*(?=-)", "λ", filename)

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
    return filename


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
    # .license is used in high volume in netbeans
    skippable = [
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
    for suffix in skippable:
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

    paths = []
    with open(filename) as f:
        for line in f:
            path = pathlib.Path(line.strip())
            if is_skippable(path):
                continue
            paths.append(path)
    # print(len(paths), "paths")

    versions: dict[str, set[str]] = {}
    subs: dict[str, set[str]] = {}
    templates: dict[str, dict[str, int]] = {}
    for path in paths:
        size = len(path.parts)
        elements: dict[str, str | None] = {
            "core": None,
            "version": None,
            "sub": None,
            "template": None,
        }
        for i, component in enumerate(path.parts):
            component_parse(i, component, size, elements)

        if elements["core"] is not None:
            if elements["core"] not in versions:
                versions[elements["core"]] = set()
            if elements["core"] not in subs:
                subs[elements["core"]] = set()
            if elements["core"] not in templates:
                templates[elements["core"]] = {}

            if elements["version"] is not None:
                versions[elements["core"]].add(elements["version"])
            if elements["sub"] is not None:
                subs[elements["core"]].add(elements["sub"])
            if elements["template"] is not None:
                if elements["template"] not in templates[elements["core"]]:
                    templates[elements["core"]][elements["template"]] = 0
                templates[elements["core"]][elements["template"]] += 1

    # Prevent BrokenPipeError when piping output to other commands
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    try:
        print_data(versions, subs, templates)
    except BrokenPipeError:
        ...


def print_data(versions: dict[str, set[str]], subs: dict[str, set[str]], templates: dict[str, dict[str, int]]) -> None:
    # Print the templates of all projects
    for core, version_set in sorted(versions.items()):
        print("---", core, "---")
        print()
        if version_set:
            print("  VERSIONS:", ", ".join(sorted(version_set)))
        if subs[core]:
            print("  SUBS:", ", ".join(sorted(subs[core])))
        print()
        for template, count in sorted(templates[core].items()):
            print(f"  {count:3d} {template}")
        print()
        print()
    sys.stdout.flush()


def variant_pattern() -> str:
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
    variants = [
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
    # .bin can also be an EXT
    # For example in opennlp
    # Which is why we do (?<=[_-])
    return "(?<=[_-])(" + "|".join(variants) + ")(?=[_.-])"


def version_parse(version: str, elements: dict[str, str | None]) -> str:
    if elements["core"] is None:
        return version
    if version.startswith(elements["core"] + "-"):
        return version[len(elements["core"]) + 1 :]
    return version


if __name__ == "__main__":
    main()
