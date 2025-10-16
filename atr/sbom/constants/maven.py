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

from __future__ import annotations

import pathlib
from typing import Final

CACHE_PATH: Final[pathlib.Path] = pathlib.Path("/tmp/sbomtool-cache.json")

PLUGIN_VERSIONS: Final[dict[str, str]] = {
    "2024-11-28T21:29:12Z": "2.9.1",
    "2024-10-08T04:31:11Z": "2.9.0",
    "2024-09-25T20:08:34Z": "2.8.2",
    "2024-08-03T22:37:32Z": "2.8.1",
    "2024-03-23T12:35:22Z": "2.8.0",
    "2024-01-16T08:02:43Z": "2.7.11",
    "2023-10-30T00:44:15Z": "2.7.10",
    "2023-05-16T18:58:36Z": "2.7.9",
    "2023-04-25T19:47:56Z": "2.7.8",
    "2023-04-17T22:41:32Z": "2.7.7",
    "2023-03-30T21:58:15Z": "2.7.6",
    "2023-02-15T23:43:55Z": "2.7.5",
    "2023-01-04T20:24:45Z": "2.7.4",
    "2022-11-10T07:37:12Z": "2.7.3",
    "2022-10-10T14:23:53Z": "2.7.2",
    "2022-07-20T04:23:22Z": "2.7.1",
    "2022-05-26T13:55:36Z": "2.7.0",
    "2022-05-03T14:19:50Z": "2.6.2",
    "2022-05-03T02:39:34Z": "2.6.1",
    "2022-04-30T05:28:10Z": "2.6.0",
    "2021-09-03T02:00:01Z": "2.5.3",
    "2021-08-19T05:29:24Z": "2.5.2",
    "2021-05-17T06:09:59Z": "2.5.1",
    "2021-05-16T06:14:27Z": "2.5.0",
    "2021-04-09T04:58:23Z": "2.4.1",
    "2021-04-01T04:09:47Z": "2.4.0",
    "2021-03-05T03:12:42Z": "2.3.0",
    "2021-01-30T23:42:19Z": "2.2.0",
    "2020-11-19T04:57:18Z": "2.1.1",
    "2020-10-12T20:09:06Z": "2.1.0",
    "2020-08-11T03:36:18Z": "2.0.3",
    "2020-07-20T01:41:20Z": "2.0.2",
    "2020-07-15T16:42:24Z": "2.0.1",
    "2020-07-14T03:45:56Z": "2.0.0",
    "2020-02-07T04:38:47Z": "1.6.4",
    "2020-02-01T04:51:27Z": "1.6.3",
    "2020-01-27T23:45:33Z": "1.6.2",
    "2020-01-24T21:33:32Z": "1.6.1",
    "2020-01-08T05:33:32Z": "1.6.0",
    "2019-11-26T21:07:06Z": "1.5.1",
    "2019-11-20T05:13:32Z": "1.5.0",
    "2019-06-19T16:41:47Z": "1.4.1",
    "2019-06-08T05:04:41Z": "1.4.0",
    "2019-01-02T20:44:14Z": "1.3.1",
    "2018-12-05T01:56:08Z": "1.3.0",
    "2018-11-28T00:27:19Z": "1.2.0",
    "2018-11-09T04:28:00Z": "1.1.3",
    "2018-07-25T20:54:37Z": "1.1.2",
    "2018-07-18T02:59:25Z": "1.1.1",
    "2018-06-07T04:20:23Z": "1.1.0",
    "2018-05-24T23:24:10Z": "1.0.1",
    "2018-05-02T16:34:05Z": "1.0.0",
}
