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

import os


def _get_development_version() -> tuple[str, str] | None:
    """Returns the version when within a development environment."""

    try:
        from dunamai import Version
    except ImportError:
        # dunamai is not installed, so probably we are not in
        # a development environment.
        return None

    try:
        version = Version.from_git()
        if version.distance > 0:
            return version.serialize(format="v{base}+{distance}.{commit}", bump=True), version.serialize(
                format="{commit}"
            )
        else:
            return version.serialize(format="v{base}"), version.serialize(format="{commit}")

    except RuntimeError:
        return None


def _get_version_from_env() -> tuple[str, str | None]:
    """Returns the version from an environment variable."""

    return os.environ.get("VERSION", "undefined"), os.environ.get("COMMIT")


# Try to determine the version from a development environment first.
# If this fails, try to get it from environment variables that are set when building a docker image.
__version__, __commit__ = _get_development_version() or _get_version_from_env()
