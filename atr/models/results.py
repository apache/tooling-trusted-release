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

from . import schema


class HashingCheck(schema.Strict):
    """Result of the task to check the hash of a file."""

    kind: Literal["hashing_check"] = schema.Field(alias="kind")
    hash_algorithm: str = schema.description("The hash algorithm used")
    hash_value: str = schema.description("The hash value of the file")
    hash_file_path: str = schema.description("The path to the hash file")


class MessageSend(schema.Strict):
    """Result of the task to send an email."""

    kind: Literal["message_send"] = schema.Field(alias="kind")
    mid: str = schema.description("The message ID of the email")
    mail_send_warnings: list[str] = schema.description("Warnings from the mail server")


class SBOMGenerateCycloneDX(schema.Strict):
    """Result of the task to generate a CycloneDX SBOM."""

    kind: Literal["sbom_generate_cyclonedx"] = schema.Field(alias="kind")
    msg: str = schema.description("The message from the SBOM generation")


class SvnImportFiles(schema.Strict):
    """Result of the task to import files from SVN."""

    kind: Literal["svn_import"] = schema.Field(alias="kind")
    msg: str = schema.description("The message from the SVN import")


class VoteInitiate(schema.Strict):
    """Result of the task to initiate a vote."""

    kind: Literal["vote_initiate"] = schema.Field(alias="kind")
    message: str = schema.description("The message from the vote initiation")
    email_to: str = schema.description("The email address the vote was sent to")
    vote_end: str = schema.description("The date and time the vote ends")
    subject: str = schema.description("The subject of the vote email")
    mid: str | None = schema.description("The message ID of the vote email")
    mail_send_warnings: list[str] = schema.description("Warnings from the mail server")


Results = Annotated[
    HashingCheck | MessageSend | SBOMGenerateCycloneDX | SvnImportFiles | VoteInitiate,
    schema.Field(discriminator="kind"),
]

ResultsAdapter = pydantic.TypeAdapter(Results)
