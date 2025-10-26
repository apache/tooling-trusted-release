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
import logging.handlers
import queue
from typing import Any, Final

PERFORMANCE: logging.Logger | None = None


def caller_name(depth: int = 1) -> str:
    frame = inspect.currentframe()
    for _ in range(depth + 1):
        if frame is None:
            break
        frame = frame.f_back

    if frame is None:
        return __name__

    module = frame.f_globals.get("__name__", "<unknown>")
    func = frame.f_code.co_name

    if func == "<module>":
        # We're at the top level
        return module

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

    return name


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


def interface_name(depth: int = 1) -> str:
    return caller_name(depth=depth)


def log(level: int, msg: str, *args: Any, **kwargs: Any) -> None:
    # Custom log level
    _event(level, msg, *args, **kwargs)


def performance(msg: str, *args: Any, **kwargs: Any) -> None:
    if PERFORMANCE is not None:
        PERFORMANCE.info(msg, *args, **kwargs)


def performance_init() -> None:
    global PERFORMANCE
    PERFORMANCE = _performance_logger()


def secret(msg: str, data: bytes, *args: Any, **kwargs: Any) -> None:
    import base64

    import nacl.encoding as encoding
    import nacl.public as public

    import atr.config as config

    conf = config.get()
    public_key_b64 = conf.LOG_PUBLIC_KEY
    if public_key_b64 is None:
        raise ValueError("LOG_PUBLIC_KEY is not set")

    recipient_pk = public.PublicKey(
        public_key_b64.encode("ascii"),
        encoder=encoding.Base64Encoder,
    )
    ciphertext = public.SealedBox(recipient_pk).encrypt(data)
    encoded_ciphertext = base64.b64encode(ciphertext).decode("ascii")
    _event(logging.INFO, f"{msg} {encoded_ciphertext}", *args, **kwargs)


def warning(msg: str, *args: Any, **kwargs: Any) -> None:
    _event(logging.WARNING, msg, *args, **kwargs)


def _caller_logger(depth: int = 1) -> logging.Logger:
    return logging.getLogger(caller_name(depth))


def _event(level: int, msg: str, *args: Any, stacklevel: int = 3, **kwargs: Any) -> None:
    logger = _caller_logger(depth=3)
    # Stack level 1 is *here*, 2 is the caller, 3 is the caller of the caller
    # I.e. _event (1), log.* (2), actual caller (3)
    logger.log(level, msg, *args, stacklevel=stacklevel, **kwargs)


def _performance_logger() -> logging.Logger:
    import atr.config as config

    class MicrosecondsFormatter(logging.Formatter):
        # Answers on a postcard if you know why Python decided to use a comma by default
        default_msec_format = "%s.%03d"

    performance: Final = logging.getLogger("log.performance")
    # Use custom formatter that properly includes microseconds
    # TODO: Is this actually UTC?
    performance_handler: Final = logging.FileHandler(config.get().PERFORMANCE_LOG_FILE, encoding="utf-8")
    performance_handler.setFormatter(MicrosecondsFormatter("%(asctime)s - %(message)s"))
    performance_queue = queue.Queue(-1)
    performance_listener = logging.handlers.QueueListener(performance_queue, performance_handler)
    performance_listener.start()
    performance.addHandler(logging.handlers.QueueHandler(performance_queue))
    performance.setLevel(logging.INFO)
    # If we don't set propagate to False then it logs to the term as well
    performance.propagate = False

    return performance
