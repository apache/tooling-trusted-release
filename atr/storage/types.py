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
from typing import TYPE_CHECKING

import atr.models.schema as schema
import atr.models.sql as sql
import atr.storage as storage


class KeyStatus(enum.Flag):
    PARSED = 0
    INSERTED = enum.auto()
    LINKED = enum.auto()
    INSERTED_AND_LINKED = INSERTED | LINKED


class Key(schema.Strict):
    status: KeyStatus
    key_model: sql.PublicSigningKey


class PublicKeyError(Exception):
    def __init__(self, key: Key, original_error: Exception):
        self.__key = key
        self.__original_error = original_error

    def __str__(self) -> str:
        return f"PublicKeyError: {self.__original_error}"

    @property
    def key(self) -> Key:
        return self.__key

    @property
    def original_error(self) -> Exception:
        return self.__original_error


if TYPE_CHECKING:
    KeyOutcomes = storage.Outcomes[Key]
    # KeyOutcomeResult = storage.OutcomeResult[Key]
    # KeyOutcomeError = storage.OutcomeError[Key, Exception]
