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

import pathlib
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

import pydantic

import atr.form as form
import atr.web as web

type Respond = Callable[[int, str], Awaitable[tuple[web.QuartResponse, int] | web.WerkzeugResponse]]

type DELETE_DIR = Literal["DELETE_DIR"]
type MOVE_FILE = Literal["MOVE_FILE"]
type REMOVE_RC_TAGS = Literal["REMOVE_RC_TAGS"]


class DeleteEmptyDirectoryForm(form.Form):
    variant: DELETE_DIR = form.value(DELETE_DIR)
    directory_to_delete: str = form.label("Directory to delete", widget=form.Widget.SELECT)


class MoveFileForm(form.Form):
    variant: MOVE_FILE = form.value(MOVE_FILE)
    source_files: form.StrList = form.label("Files to move")
    target_directory: str = form.label("Target directory")

    @pydantic.model_validator(mode="after")
    def validate_move(self) -> "MoveFileForm":
        if not self.source_files:
            raise ValueError("Please select at least one file to move.")

        source_paths = [pathlib.Path(sf) for sf in self.source_files]
        target_dir = pathlib.Path(self.target_directory)
        for source_path in source_paths:
            if source_path.parent == target_dir:
                raise ValueError(f"Target directory cannot be the same as the source directory for {source_path.name}.")
        return self


class RemoveRCTagsForm(form.Empty):
    variant: REMOVE_RC_TAGS = form.value(REMOVE_RC_TAGS)


type FinishForm = Annotated[
    DeleteEmptyDirectoryForm | MoveFileForm | RemoveRCTagsForm,
    form.DISCRIMINATOR,
]
