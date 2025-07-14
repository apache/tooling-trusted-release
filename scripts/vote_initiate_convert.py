#!/usr/bin/env python3
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

"""Convert legacy vote_initiate task results to the new validated format."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Final, cast

import pydantic
import sqlalchemy
import sqlmodel

import atr.db as db
import atr.models.results as results
import atr.models.sql as sql

_LOG_PREFIX: Final = "[vote_convert]"


def _write(message: str) -> None:
    """Print and flush a log line."""
    print(f"{_LOG_PREFIX} {message}")
    sys.stdout.flush()


async def _raw_result(data: db.Session, task_id: int) -> Any | None:
    """Return the raw JSON column value for a given task id, bypassing the type adapter."""
    stmt = sqlalchemy.text("SELECT result FROM task WHERE id = :id").bindparams(id=task_id)
    result_row = await data.execute(stmt)
    row = result_row.one_or_none()
    if row is None:
        return None
    # The first column is the raw JSON value
    return row[0]


def _convert_legacy(raw_val: Any) -> results.VoteInitiate | None:
    """Convert legacy JSON payloads to VoteInitiate, return None if impossible."""

    if raw_val in (None, "", "[]", []):
        raise ValueError("Empty or null result")

    # If it's bytes, decode to str first
    if isinstance(raw_val, bytes | bytearray):
        raw_val = raw_val.decode("utf-8", errors="replace")

    # At this point, raw_val is usually a JSON-encoded string (e.g. "[\"{...}\"]")
    # Normalise to Python data structure
    if isinstance(raw_val, str):
        try:
            raw_val = json.loads(raw_val)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Top level JSON decode failed: {exc}") from exc

    return _convert_legacy_continued(raw_val)


def _convert_legacy_continued(raw_val: Any) -> results.VoteInitiate:
    # If we now have list or tuple, take the first element
    if isinstance(raw_val, list | tuple):
        if not raw_val:
            raise ValueError("List payload empty")
        raw_val = raw_val[0]
        # That element might itself be a JSON string
        if isinstance(raw_val, str):
            try:
                raw_val = json.loads(raw_val)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Inner JSON decode failed: {exc}") from exc

    # Expect raw_val to be dict now
    if not isinstance(raw_val, dict):
        raise ValueError(f"Unexpected type after normalisation: {type(raw_val).__name__}")

    # Inject the discriminator
    raw_val.setdefault("kind", "vote_initiate")

    # Normalise optional or missing fields expected by VoteInitiate
    raw_val.setdefault("mail_send_warnings", [])
    # Ensure type is list[str]
    if not isinstance(raw_val["mail_send_warnings"], list):
        raw_val["mail_send_warnings"] = [str(raw_val["mail_send_warnings"])]

    try:
        return results.VoteInitiate.model_validate(raw_val)
    except pydantic.ValidationError as exc:
        raise ValueError(f"Pydantic validation failed: {exc}") from exc


async def audit_vote_initiate_results() -> None:
    """Upgrade legacy vote_initiate task results to the new validated format."""

    await db.init_database_for_worker()

    async with db.session() as data:
        stmt = sqlmodel.select(sql.Task).where(sql.Task.task_type == sql.TaskType.VOTE_INITIATE)
        result = await data.execute(stmt)
        tasks = result.scalars().all()

        _write(f"Found {len(tasks)} vote_initiate tasks total")

        upgraded = 0
        skipped = 0
        for task in tasks:
            if isinstance(task.result, results.VoteInitiate):
                # Already correct
                continue

            raw_val = await _raw_result(data, task.id)
            try:
                new_val = _convert_legacy(raw_val)
            except ValueError as err:
                skipped += 1
                preview = (
                    f"{str(raw_val)[:120]}..." if isinstance(raw_val, str) and len(str(raw_val)) > 120 else str(raw_val)
                )
                _write(f"Task id={task.id}: conversion error -> {err}; raw preview: {preview}")
                continue

            # Apply upgrade in current transaction
            task.result = cast("results.Results", new_val)
            # Ensure SQL UPDATE issued before next iteration
            await data.flush()
            upgraded += 1

            _write(f"Task id={task.id}: upgraded legacy result -> VoteInitiate")

        # Commit all changes once at the end of the context manager
        await data.commit()

        _write(f"Upgrade complete. Upgraded: {upgraded}, skipped (unconvertible): {skipped}")


async def amain() -> None:
    await audit_vote_initiate_results()


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
