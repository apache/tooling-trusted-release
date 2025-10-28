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

import atr.get.announce as announce
import atr.get.candidate as candidate
import atr.get.committees as committees
import atr.get.compose as compose
import atr.get.distribution as distribution
import atr.get.docs as docs
import atr.get.download as download
import atr.get.draft as draft
import atr.get.file as file
import atr.get.finish as finish
import atr.get.ignores as ignores
import atr.get.keys as keys
import atr.get.preview as preview
import atr.get.projects as projects
import atr.get.vote as vote

ROUTES_MODULE: Final[Literal[True]] = True

__all__ = [
    "announce",
    "candidate",
    "committees",
    "compose",
    "distribution",
    "docs",
    "download",
    "draft",
    "file",
    "finish",
    "ignores",
    "keys",
    "preview",
    "projects",
    "vote",
]
