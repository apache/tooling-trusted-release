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
import subprocess
import tempfile

import yyjson

from . import models


def sbomqs_total_score(value: pathlib.Path | str | yyjson.Document) -> float:
    args = ["sbomqs", "compliance", "--ntia", "--json"]
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as tf:
        match value:
            case yyjson.Document():
                tf.write(value.dumps())
            case pathlib.Path():
                tf.write(pathlib.Path(value).read_text(encoding="utf-8"))
            case str():
                tf.write(value)
        tf.flush()
        args.append(tf.name)

        proc = subprocess.run(
            args,
            text=True,
            capture_output=True,
        )
    if proc.returncode != 0:
        err = proc.stderr.strip() or "sbomqs failed"
        raise RuntimeError(err)
    report = models.sbomqs.SBOMQSReport.model_validate_json(proc.stdout)
    return report.summary.total_score
