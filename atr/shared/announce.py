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


class AnnounceForm(form.Form):
    """Form for announcing a release preview."""

    revision_number: str = form.label("Revision number", widget=form.Widget.HIDDEN)
    mailing_list: str = form.label(
        "Send vote email to",
        widget=form.Widget.CUSTOM,
    )
    subject: str = form.label("Subject")
    body: str = form.label("Body", widget=form.Widget.CUSTOM)
    download_path_suffix: str = form.label("Download path suffix", widget=form.Widget.CUSTOM)
    confirm_announce: form.Bool = form.label("Confirm")

    @pydantic.field_validator("download_path_suffix")
    @classmethod
    def validate_and_normalize_download_path_suffix(cls, suffix: str) -> str:
        if (".." in suffix) or ("//" in suffix):
            raise ValueError("Download path suffix must not contain .. or //")
        if suffix.startswith("./"):
            suffix = suffix[1:]
        elif suffix == ".":
            suffix = "/"
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        if not suffix.endswith("/"):
            suffix = suffix + "/"
        if "/." in suffix:
            raise ValueError("Download path suffix must not contain /.")
        return suffix

    @pydantic.model_validator(mode="after")
    def validate_confirm(self) -> "AnnounceForm":
        if not self.confirm_announce:
            raise ValueError("You must confirm the announcement by checking the box")
        return self
