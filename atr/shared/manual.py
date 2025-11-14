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

from typing import Literal

import pydantic

import atr.form as form


class ResolveVoteForm(form.Form):
    vote_result: Literal["Passed", "Failed"] = form.label("Vote result", widget=form.Widget.RADIO)
    vote_thread_url: str = form.label("Vote thread URL")
    vote_result_url: str = form.label("Vote result URL")

    @pydantic.field_validator("vote_thread_url", "vote_result_url", mode="after")
    @classmethod
    def validate_urls(cls, value: str) -> str:
        if not value.startswith("https://lists.apache.org/thread/"):
            raise ValueError("URL must be a valid Apache email thread URL")
        return value
