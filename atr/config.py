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
import secrets
from typing import Final

import decouple

_MB: Final = 1024 * 1024
_GB: Final = 1024 * _MB


def _config_secrets(key: str, state_dir: str, default: str | None = None, cast: type = str) -> str | None:
    secrets_path = os.path.join(state_dir, "secrets.ini")
    try:
        repo_ini = decouple.RepositoryIni(secrets_path)
        config_obj = decouple.Config(repo_ini)
        return config_obj.get(key, default=default, cast=cast)
    except FileNotFoundError:
        return decouple.config(key, default=default, cast=cast)


class AppConfig:
    APP_HOST = decouple.config("APP_HOST", default="localhost")
    SSH_HOST = decouple.config("SSH_HOST", default="0.0.0.0")
    SSH_PORT = decouple.config("SSH_PORT", default=2222, cast=int)
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    STATE_DIR = decouple.config("STATE_DIR", default=os.path.join(PROJECT_ROOT, "state"))
    LDAP_BIND_DN = _config_secrets("LDAP_BIND_DN", STATE_DIR, default=None, cast=str)
    LDAP_BIND_PASSWORD = _config_secrets("LDAP_BIND_PASSWORD", STATE_DIR, default=None, cast=str)
    PUBSUB_URL = _config_secrets("PUBSUB_URL", STATE_DIR, default=None, cast=str)
    PUBSUB_USER = _config_secrets("PUBSUB_USER", STATE_DIR, default=None, cast=str)
    PUBSUB_PASSWORD = _config_secrets("PUBSUB_PASSWORD", STATE_DIR, default=None, cast=str)
    SVN_TOKEN = _config_secrets("SVN_TOKEN", STATE_DIR, default=None, cast=str)

    DEBUG = False
    TEMPLATES_AUTO_RELOAD = False
    USE_BLOCKBUSTER = False
    SECRET_KEY = decouple.config("SECRET_KEY", default=secrets.token_hex(128 // 8))
    WTF_CSRF_ENABLED = decouple.config("WTF_CSRF_ENABLED", default=True, cast=bool)
    DOWNLOADS_STORAGE_DIR = os.path.join(STATE_DIR, "downloads")
    FINISHED_STORAGE_DIR = os.path.join(STATE_DIR, "finished")
    UNFINISHED_STORAGE_DIR = os.path.join(STATE_DIR, "unfinished")
    # TODO: By convention this is at /x1/, but we can symlink it here perhaps?
    # TODO: We need to get Puppet to check SVN out initially, or do it manually
    SVN_STORAGE_DIR = os.path.join(STATE_DIR, "svn")
    SQLITE_DB_PATH = decouple.config("SQLITE_DB_PATH", default="atr.db")

    # Apache RAT configuration
    APACHE_RAT_JAR_PATH = decouple.config("APACHE_RAT_JAR_PATH", default="/opt/tools/apache-rat-0.16.1.jar")
    # Maximum content length for requests
    MAX_CONTENT_LENGTH: int = decouple.config("MAX_CONTENT_LENGTH", default=512 * _MB, cast=int)
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


class DebugConfig(AppConfig):
    DEBUG = True
    TEMPLATES_AUTO_RELOAD = True
    USE_BLOCKBUSTER = False


class Mode(enum.Enum):
    Debug = "Debug"
    Production = "Production"
    Profiling = "Profiling"


_global_mode: Mode | None = None


class ProductionConfig(AppConfig): ...


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
        config = _CONFIG_DICT[get_mode()]
    except KeyError:
        exit("Error: Invalid <mode>. Expected values [Debug, Production, Profiling].")

    absolute_paths = [
        (config.PROJECT_ROOT, "PROJECT_ROOT"),
        (config.STATE_DIR, "STATE_DIR"),
        (config.DOWNLOADS_STORAGE_DIR, "DOWNLOADS_STORAGE_DIR"),
        (config.FINISHED_STORAGE_DIR, "FINISHED_STORAGE_DIR"),
        (config.UNFINISHED_STORAGE_DIR, "UNFINISHED_STORAGE_DIR"),
        (config.SVN_STORAGE_DIR, "SVN_STORAGE_DIR"),
    ]
    relative_paths = [
        (config.SQLITE_DB_PATH, "SQLITE_DB_PATH"),
    ]

    for path, name in absolute_paths:
        if not path.startswith("/"):
            raise RuntimeError(f"{name} must be an absolute path")
    for path, name in relative_paths:
        if path.startswith("/"):
            raise RuntimeError(f"{name} must be a relative path")

    return config


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
