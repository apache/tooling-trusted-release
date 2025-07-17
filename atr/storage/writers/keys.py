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

# Removing this will cause circular imports
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import atr.db as db
import atr.storage as storage
import atr.util as util

if TYPE_CHECKING:
    from collections.abc import Generator


class CommitteeMember:
    def __init__(
        self, credentials: storage.WriteAsCommitteeMember, data: db.Session, asf_uid: str, committee_name: str
    ):
        if credentials.validate_at_runtime:
            if credentials.authenticated is not True:
                raise storage.AccessError("Writer is not authenticated")
        self.__credentials = credentials
        self.__data = data
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name

    def upload(self, keys_file_text: str) -> Generator[str]:
        for key_block in util.parse_key_blocks(keys_file_text):
            try:
                for fingerprint in self.__load_key_block(key_block):
                    yield fingerprint.lower()
            except Exception as e:
                logging.error(f"Error loading key block: {e}")

    def __load_key_block(self, key_block: str) -> Generator[str]:
        if False:
            yield ""
