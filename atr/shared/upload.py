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

from typing import Annotated, Literal

import pydantic

import atr.form as form

type ADD_FILES = Literal["add_files"]
type SVN_IMPORT = Literal["svn_import"]


class AddFilesForm(form.Form):
    variant: ADD_FILES = form.value(ADD_FILES)
    file_data: form.FileList = form.label("Files", "Select the files to upload.")
    file_name: form.Filename = form.label(
        "File name",
        "Optional: Enter a file name to use when saving the file in the release candidate. "
        "Only available when uploading a single file.",
    )

    @pydantic.field_validator("file_name", mode="after")
    @classmethod
    def validate_file_name_with_files(cls, value: form.Filename, info: pydantic.ValidationInfo) -> form.Filename:
        # We can only get file_data if it comes before this field
        # TODO: Figure out how to use a model validator but associate an error with a field
        # https://github.com/pydantic/pydantic/issues/8092
        # https://github.com/pydantic/pydantic/issues/9686
        # https://github.com/pydantic/pydantic-core/pull/1413
        file_data = info.data.get("file_data") or []
        if value and (len(file_data) != 1):
            raise ValueError("Filename can only be used when uploading a single file")
        return value


class SvnImportForm(form.Form):
    variant: SVN_IMPORT = form.value(SVN_IMPORT)
    svn_url: form.URL = form.label(
        "SVN URL",
        "The HTTP or HTTPS URL to the public SVN directory.",
        widget=form.Widget.URL,
    )
    revision: str = form.label(
        "Revision",
        "Specify an SVN revision number or leave as HEAD for the latest.",
        default="HEAD",
    )
    target_subdirectory: form.Filename = form.label(
        "Target subdirectory",
        "Optional: Subdirectory to place imported files, defaulting to the root.",
    )


type UploadForm = Annotated[
    AddFilesForm | SvnImportForm,
    form.DISCRIMINATOR,
]
