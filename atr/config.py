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

from decouple import config

from atr.db.models import __file__ as data_models_file

MB = 1024 * 1024
GB = 1024 * MB


class AppConfig:
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    STATE_DIR = os.path.join(PROJECT_ROOT, "state")
    DEBUG = False
    USE_BLOCKBUSTER = False

    RELEASE_STORAGE_DIR = os.path.join(STATE_DIR, "releases")
    DATA_MODELS_FILE = data_models_file

    SQLITE_URL = config("SQLITE_URL", default="sqlite+aiosqlite:///./atr.db")

    # Apache RAT configuration
    APACHE_RAT_JAR_PATH = config("APACHE_RAT_JAR_PATH", default="state/apache-rat-0.16.1.jar")
    # Maximum size limit for archive extraction
    MAX_EXTRACT_SIZE = config("MAX_EXTRACT_SIZE", default=2 * GB, cast=int)
    # Chunk size for reading files during extraction
    EXTRACT_CHUNK_SIZE = config("EXTRACT_CHUNK_SIZE", default=4 * MB, cast=int)

    ADMIN_USERS = frozenset(
        {
            "cwells",
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
