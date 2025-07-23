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

import atr.models.results as results
import atr.models.schema as schema
import atr.storage as storage
import atr.tasks.checks as checks


class ImportFile(schema.Strict):
    """Import a KEYS file from a draft release candidate revision."""

    asf_uid: str
    project_name: str
    version_name: str


@checks.with_model(ImportFile)
async def import_file(args: ImportFile) -> results.Results | None:
    """Import a KEYS file from a draft release candidate revision."""
    async with storage.write(args.asf_uid) as write:
        wacm = await write.as_project_committee_member(args.project_name)
        outcomes = await wacm.keys.import_keys_file(args.project_name, args.version_name)
        if outcomes.any_exception:
            # TODO: Log this? This code is unused anyway
            pass
    return None
