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

"""ignores.py"""

import enum
from typing import Annotated, Literal

import pydantic

import atr.form as form
import atr.models.sql as sql

type ADD = Literal["add"]
type DELETE = Literal["delete"]
type UPDATE = Literal["update"]


class IgnoreStatus(enum.Enum):
    """Wrapper enum for ignore status."""

    NO_STATUS = "-"
    EXCEPTION = "Exception"
    FAILURE = "Failure"
    WARNING = "Warning"


def ignore_status_to_sql(status: IgnoreStatus | None) -> sql.CheckResultStatusIgnore | None:
    """Convert wrapper enum to SQL enum."""
    if (status is None) or (status == IgnoreStatus.NO_STATUS):
        return None
    match status:
        case IgnoreStatus.EXCEPTION:
            return sql.CheckResultStatusIgnore.EXCEPTION
        case IgnoreStatus.FAILURE:
            return sql.CheckResultStatusIgnore.FAILURE
        case IgnoreStatus.WARNING:
            return sql.CheckResultStatusIgnore.WARNING


def sql_to_ignore_status(status: sql.CheckResultStatusIgnore | None) -> IgnoreStatus:
    """Convert SQL enum to wrapper enum."""
    if status is None:
        return IgnoreStatus.NO_STATUS
    match status:
        case sql.CheckResultStatusIgnore.EXCEPTION:
            return IgnoreStatus.EXCEPTION
        case sql.CheckResultStatusIgnore.FAILURE:
            return IgnoreStatus.FAILURE
        case sql.CheckResultStatusIgnore.WARNING:
            return IgnoreStatus.WARNING


class AddIgnoreForm(form.Form):
    variant: ADD = form.value(ADD)
    release_glob: str = form.label("Release pattern", default="")
    revision_number: str = form.label("Revision number (literal)", default="")
    checker_glob: str = form.label("Checker pattern", default="")
    primary_rel_path_glob: str = form.label("Primary rel path pattern", default="")
    member_rel_path_glob: str = form.label("Member rel path pattern", default="")
    status: form.Enum[IgnoreStatus] = form.label(
        "Status",
        widget=form.Widget.SELECT,
    )
    message_glob: str = form.label("Message pattern", default="")

    @pydantic.model_validator(mode="after")
    def validate_at_least_one_field(self) -> "AddIgnoreForm":
        has_status = self.status != IgnoreStatus.NO_STATUS  # type: ignore[comparison-overlap]
        if not any(
            [
                self.release_glob,
                self.revision_number,
                self.checker_glob,
                self.primary_rel_path_glob,
                self.member_rel_path_glob,
                has_status,
                self.message_glob,
            ]
        ):
            raise ValueError("At least one field must be set")
        return self


class DeleteIgnoreForm(form.Form):
    variant: DELETE = form.value(DELETE)
    id: int = form.label("ID", widget=form.Widget.HIDDEN)


class UpdateIgnoreForm(form.Form):
    variant: UPDATE = form.value(UPDATE)
    id: int = form.label("ID", widget=form.Widget.HIDDEN)
    release_glob: str = form.label("Release pattern", default="")
    revision_number: str = form.label("Revision number (literal)", default="")
    checker_glob: str = form.label("Checker pattern", default="")
    primary_rel_path_glob: str = form.label("Primary rel path pattern", default="")
    member_rel_path_glob: str = form.label("Member rel path pattern", default="")
    status: form.Enum[IgnoreStatus] = form.label(
        "Status",
        widget=form.Widget.SELECT,
    )
    message_glob: str = form.label("Message pattern", default="")

    @pydantic.model_validator(mode="after")
    def validate_at_least_one_field(self) -> "UpdateIgnoreForm":
        has_status = self.status != IgnoreStatus.NO_STATUS  # type: ignore[comparison-overlap]
        if not any(
            [
                self.release_glob,
                self.revision_number,
                self.checker_glob,
                self.primary_rel_path_glob,
                self.member_rel_path_glob,
                has_status,
                self.message_glob,
            ]
        ):
            raise ValueError("At least one field must be set")
        return self


type IgnoreForm = Annotated[
    AddIgnoreForm | DeleteIgnoreForm | UpdateIgnoreForm,
    form.DISCRIMINATOR,
]
