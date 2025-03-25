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

from typing import Any, Final

import atr.db.models as models

QUEUED: Final = models.TaskStatus.QUEUED
ACTIVE: Final = models.TaskStatus.ACTIVE
COMPLETED: Final = models.TaskStatus.COMPLETED
FAILED: Final = models.TaskStatus.FAILED


class Error(Exception):
    """Error during task execution."""

    def __init__(self, message: str, *result: Any) -> None:
        self.message = message
        self.result = tuple(result)


def results_as_tuple(item: Any) -> tuple[Any, ...]:
    """Ensure that returned results are structured as a tuple."""
    if not isinstance(item, tuple):
        return (item,)
    return item
