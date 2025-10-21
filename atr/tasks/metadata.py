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

import aiohttp

import atr.datasources.apache as apache
import atr.log as log
import atr.models.results as results
import atr.models.schema as schema
import atr.tasks.checks as checks


class Update(schema.Strict):
    """Arguments for the task to update metadata from remote data sources."""

    asf_uid: str = schema.description("The ASF UID of the user triggering the update")


class UpdateError(Exception):
    pass


@checks.with_model(Update)
async def update(args: Update) -> results.Results | None:
    """Update metadata from remote data sources."""
    log.info(f"Starting metadata update for user {args.asf_uid}")

    try:
        added_count, updated_count = await apache.update_metadata()

        log.info(
            f"Metadata update completed successfully: added {added_count}, updated {updated_count}",
        )
        return results.MetadataUpdate(
            kind="metadata_update",
            added_count=added_count,
            updated_count=updated_count,
        )

    except aiohttp.ClientError as e:
        error_msg = f"Failed to fetch data from remote data sources: {e!s}"
        log.error(f"Metadata update failed: {error_msg}")
        raise UpdateError(error_msg) from e
    except Exception as e:
        error_msg = f"Unexpected error during metadata update: {e!s}"
        log.exception("Metadata update failed with unexpected error")
        raise UpdateError(error_msg) from e
