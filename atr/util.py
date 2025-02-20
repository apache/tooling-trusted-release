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
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Annotated, Any

from pydantic import GetCoreSchemaHandler, TypeAdapter, create_model
from pydantic_core import CoreSchema, core_schema
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


def _get_dict_to_list_inner_type_adapter(source_type: Any, key: str) -> TypeAdapter[dict[Any, Any]]:
    root_adapter = TypeAdapter(source_type)
    schema = root_adapter.core_schema

    assert schema["type"] == "list"
    assert (item_schema := schema["items_schema"])
    assert item_schema["type"] == "model"
    assert (cls := item_schema["cls"])  # noqa: RUF018

    fields = cls.model_fields

    assert (key_field := fields.get(key))  # noqa: RUF018
    assert (other_fields := {k: v for k, v in fields.items() if k != key})  # noqa: RUF018

    model_name = f"{cls.__name__}Inner"
    inner_model = create_model(model_name, **{k: (Any, v) for k, v in other_fields.items()})  # type: ignore
    return TypeAdapter(dict[Annotated[Any, key_field], inner_model])  # type: ignore


def _get_dict_to_list_validator(inner_adapter: TypeAdapter[dict[Any, Any]], key: str) -> Any:
    def validator(val: Any) -> Any:
        if isinstance(val, dict):
            validated = inner_adapter.validate_python(val)
            return [{key: k, **{f: getattr(v, f) for f in v.model_fields}} for k, v in validated.items()]

        return val

    return validator


# from https://github.com/pydantic/pydantic/discussions/8755#discussioncomment-8417979
@dataclass
class DictToList:
    key: str

    def __get_pydantic_core_schema__(
        self,
        source_type: Any,
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        adapter = _get_dict_to_list_inner_type_adapter(source_type, self.key)

        return core_schema.no_info_before_validator_function(
            _get_dict_to_list_validator(adapter, self.key),
            handler(source_type),
        )
