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


def _get_version_from_git() -> tuple[str, str] | None:
    """Returns the version when within a development environment."""

    try:
        import dunamai
    except ImportError:
        # dunamai is not installed, so probably we are not in
        # a development environment.
        return None

    try:
        # We start in state/, so we need to go up one level
        version = dunamai.Version.from_git()
        if version.distance > 0:
            dirty = "+dirty" if version.dirty else ""
            # The development version number should reflect the next release that is going to be cut,
            # indicating how many commits have already going into that since the last release.
            # e.g. v0.2.0.dev100-abcdef means that there have been already 100 commits since the last release
            # (which presumably was 0.1.x). We explicitly bump the minor version for the next release.
            # The commit hash is added to the version string for convenience reasons.
            return f"{version.bump(1).serialize(format='v{base}.dev{distance}-{commit}')}{dirty}", version.serialize(
                format="{commit}"
            )
            # another option is to do a format like "v0.1.0+100.abcdef" which indicates that that version
            # is 100 commits past the last release which was "v0.1.0".
            # return version.serialize(format="v{base}+{distance}.{commit}"), version.serialize(
            #     format="{commit}"
            # )
        else:
            return version.serialize(format="v{base}"), version.serialize(format="{commit}")

    except RuntimeError:
        return None


def _get_version_from_version_module() -> tuple[str, str] | None:
    """Returns the version from _version module if it exists."""

    try:
        import atr._version  # pyright: ignore [reportMissingImports]

        return atr._version.ATR_VERSION, atr._version.ATR_COMMIT
    except ImportError:
        return None


def _get_undefined() -> tuple[str, str]:
    return "undefined", "undefined"


# Try to determine the version from a development environment first.
# If this fails, try to get it from environment variables that are set when building a docker image.
# We don't use __version__ and __commit__ as these are not reserved words in Python
version, commit = _get_version_from_git() or _get_version_from_version_module() or _get_undefined()


if __name__ == "__main__":
    """Will output version / commit info from git tags if available."""
    version, commit = _get_version_from_git() or _get_undefined()

    print(f"""
ATR_VERSION = '{version}'
ATR_COMMIT = '{commit}'
""")
