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

from typing import Final, Literal

import atr.post.announce as announce
import atr.post.candidate as candidate
import atr.post.distribution as distribution
import atr.post.draft as draft
import atr.post.finish as finish
import atr.post.ignores as ignores
import atr.post.keys as keys
import atr.post.preview as preview
import atr.post.projects as projects
import atr.post.resolve as resolve
import atr.post.revisions as revisions
import atr.post.sbom as sbom
import atr.post.start as start
import atr.post.tokens as tokens
import atr.post.upload as upload
import atr.post.vote as vote

ROUTES_MODULE: Final[Literal[True]] = True

__all__ = [
    "announce",
    "candidate",
    "distribution",
    "draft",
    "finish",
    "ignores",
    "keys",
    "preview",
    "projects",
    "resolve",
    "revisions",
    "sbom",
    "start",
    "tokens",
    "upload",
    "vote",
]
