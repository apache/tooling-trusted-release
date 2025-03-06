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
from enum import Enum
from typing import Any, TypeVar

from decouple import config

from atr.db.models import __file__ as data_models_file

MB = 1024 * 1024
GB = 1024 * MB

T = TypeVar("T")


def ensure_type(value: Any, expected_type: type[T]) -> T:
    if not isinstance(value, expected_type):
        raise TypeError(f"Expected {expected_type.__name__}, got {type(value).__name__}")
    return value


class AppConfig:
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    STATE_DIR = os.path.join(PROJECT_ROOT, "state")
    DEBUG = False
    TEMPLATES_AUTO_RELOAD = False
    USE_BLOCKBUSTER = False

    RELEASE_STORAGE_DIR = os.path.join(STATE_DIR, "releases")
    DATA_MODELS_FILE = data_models_file

    # TODO: Understand why cast=str doesn't satisfy the type checker
    SQLITE_DB_PATH: str = ensure_type(config("SQLITE_DB_PATH", default="/atr.db"), str)

    # Apache RAT configuration
    APACHE_RAT_JAR_PATH: str = ensure_type(config("APACHE_RAT_JAR_PATH", default="state/apache-rat-0.16.1.jar"), str)
    # Maximum size limit for archive extraction
    MAX_EXTRACT_SIZE: int = config("MAX_EXTRACT_SIZE", default=2 * GB, cast=int)
    # Chunk size for reading files during extraction
    EXTRACT_CHUNK_SIZE: int = config("EXTRACT_CHUNK_SIZE", default=4 * MB, cast=int)

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


class ConfigMode(Enum):
    Debug = "Debug"
    Production = "Production"
    Profiling = "Profiling"


# Load all possible configurations
config_dict = {
    ConfigMode.Debug: DebugConfig,
    ConfigMode.Production: ProductionConfig,
    ConfigMode.Profiling: ProfilingConfig,
}

_CONFIG_MODE = None


def get_config_mode() -> ConfigMode:
    global _CONFIG_MODE

    if _CONFIG_MODE is None:
        if config("PROFILING", default=False, cast=bool):
            config_mode = ConfigMode.Profiling
        elif config("PRODUCTION", default=False, cast=bool):
            config_mode = ConfigMode.Production
        else:
            config_mode = ConfigMode.Debug

        _CONFIG_MODE = config_mode

    return _CONFIG_MODE


def get_config() -> type[AppConfig]:
    try:
        return config_dict[get_config_mode()]
    except KeyError:
        exit("Error: Invalid <config_mode>. Expected values [Debug, Production, Profiling].")


# WARNING: Don't run with debug turned on in production!
