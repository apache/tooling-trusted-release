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

import hashlib
from functools import cache
from pathlib import Path

from quart import current_app


@cache
def get_admin_users() -> set[str]:
    return set(current_app.config["ADMIN_USERS"])


def is_admin(user_id: str | None) -> bool:
    """Check if a user is an admin."""
    if user_id is None:
        return False
    return user_id in get_admin_users()


def get_release_storage_dir() -> str:
    return str(current_app.config["RELEASE_STORAGE_DIR"])


def compute_sha3_256(file_data: bytes) -> str:
    """Compute SHA3-256 hash of file data."""
    return hashlib.sha3_256(file_data).hexdigest()


def compute_sha512(file_path: Path) -> str:
    """Compute SHA-512 hash of a file."""
    sha512 = hashlib.sha512()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha512.update(chunk)
    return sha512.hexdigest()
