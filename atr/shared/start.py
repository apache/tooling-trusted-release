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

import pydantic

import atr.form as form
import atr.util as util


class StartReleaseForm(form.Form):
    version_name: str = form.label(
        "Version",
        "Enter the version string for this new release. Examples: 1.2.3 or 2.5-M1",
    )

    @pydantic.field_validator("version_name", mode="after")
    @classmethod
    def validate_version_name(cls, value: str) -> str:
        if error := util.version_name_error(value):
            raise ValueError(error)
        return value
