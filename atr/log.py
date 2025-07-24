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

import inspect
import logging
from typing import Any


def critical(msg: str, *args: Any, **kwargs: Any) -> None:
    _event(logging.CRITICAL, msg, *args, **kwargs)


def debug(msg: str, *args: Any, **kwargs: Any) -> None:
    _event(logging.DEBUG, msg, *args, **kwargs)


def error(msg: str, *args: Any, **kwargs: Any) -> None:
    _event(logging.ERROR, msg, *args, **kwargs)


def exception(msg: str, *args: Any, **kwargs: Any) -> None:
    kwargs.setdefault("exc_info", True)
    _event(logging.ERROR, msg, *args, **kwargs)


def info(msg: str, *args: Any, **kwargs: Any) -> None:
    _event(logging.INFO, msg, *args, **kwargs)


def log(level: int, msg: str, *args: Any, **kwargs: Any) -> None:
    # Custom log level
    _event(level, msg, *args, **kwargs)


def warning(msg: str, *args: Any, **kwargs: Any) -> None:
    _event(logging.WARNING, msg, *args, **kwargs)


def _caller_logger(depth: int = 1) -> logging.Logger:
    frame = inspect.currentframe()
    for _ in range(depth + 1):
        if frame is None:
            break
        frame = frame.f_back

    if frame is None:
        return logging.getLogger(__name__)

    module = frame.f_globals.get("__name__", "<unknown>")
    func = frame.f_code.co_name

    if func == "<module>":
        # We're at the top level
        return logging.getLogger(module)

    # Are we in a class?
    # There is probably a better way to do this
    cls_name = None
    if "self" in frame.f_locals:
        cls_name = frame.f_locals["self"].__class__.__name__
    elif ("cls" in frame.f_locals) and isinstance(frame.f_locals["cls"], type):
        cls_name = frame.f_locals["cls"].__name__

    if cls_name:
        name = f"{module}.{cls_name}.{func}"
    else:
        name = f"{module}.{func}"

    return logging.getLogger(name)


def _event(level: int, msg: str, *args: Any, stacklevel: int = 3, **kwargs: Any) -> None:
    logger = _caller_logger(depth=2)
    # Stack level 1 is *here*, 2 is the caller, 3 is the caller of the caller
    # I.e. _event (1), log.* (2), actual caller (3)
    logger.log(level, msg, *args, stacklevel=stacklevel, **kwargs)
