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

import enum
import os
from typing import Final

import decouple

_MB: Final = 1024 * 1024
_GB: Final = 1024 * _MB


class Mode(enum.Enum):
    Debug = "Debug"
    Production = "Production"
    Profiling = "Profiling"


_global_mode: Mode | None = None


class AppConfig:
    SSH_HOST = decouple.config("SSH_HOST", default="0.0.0.0")
    SSH_PORT = decouple.config("SSH_PORT", default=2222, cast=int)
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    STATE_DIR = os.path.join(PROJECT_ROOT, "state")
    DEBUG = False
    TEMPLATES_AUTO_RELOAD = False
    USE_BLOCKBUSTER = False
    PHASE_STORAGE_DIR = os.path.join(STATE_DIR, "phase")
    SQLITE_DB_PATH = decouple.config("SQLITE_DB_PATH", default="/atr.db")

    # Apache RAT configuration
    APACHE_RAT_JAR_PATH = decouple.config("APACHE_RAT_JAR_PATH", default="/opt/tools/apache-rat-0.16.1.jar")
    # Maximum size limit for archive extraction
    MAX_EXTRACT_SIZE: int = decouple.config("MAX_EXTRACT_SIZE", default=2 * _GB, cast=int)
    # Chunk size for reading files during extraction
    EXTRACT_CHUNK_SIZE: int = decouple.config("EXTRACT_CHUNK_SIZE", default=4 * _MB, cast=int)

    # FIXME: retrieve the list of admin users from LDAP or oath session / isRoot
    ADMIN_USERS = frozenset(
        {
            "cwells",
            "dfoulks",
            "fluxo",
            "gmcdonald",
            "humbedooh",
            "sbp",
            "tn",
            "wave",
        }
    )


class ProductionConfig(AppConfig): ...


class DebugConfig(AppConfig):
    DEBUG = True
    TEMPLATES_AUTO_RELOAD = True
    USE_BLOCKBUSTER = False


class ProfilingConfig(AppConfig):
    DEBUG = False
    TEMPLATES_AUTO_RELOAD = False
    USE_BLOCKBUSTER = True


# Load all possible configurations
_CONFIG_DICT: Final = {
    Mode.Debug: DebugConfig,
    Mode.Production: ProductionConfig,
    Mode.Profiling: ProfilingConfig,
}


def get() -> type[AppConfig]:
    try:
        return _CONFIG_DICT[get_mode()]
    except KeyError:
        exit("Error: Invalid <mode>. Expected values [Debug, Production, Profiling].")


def get_mode() -> Mode:
    global _global_mode

    if _global_mode is None:
        if decouple.config("PROFILING", default=False, cast=bool):
            _global_mode = Mode.Profiling
        elif decouple.config("PRODUCTION", default=False, cast=bool):
            _global_mode = Mode.Production
        else:
            _global_mode = Mode.Debug

    return _global_mode
