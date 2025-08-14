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

import datetime as datetime
import functools
import secrets as secrets
from typing import TYPE_CHECKING, Any, Final

import asfquart.base as base
import jwt
import quart

import atr.config as config

_SECRET_KEY: Final[str] = config.get().SECRET_KEY
_ALGORITHM: Final[str] = "HS256"

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Coroutine


def issue(uid: str, *, ttl: int = 90 * 60) -> str:
    now = datetime.datetime.now(tz=datetime.UTC)
    payload = {
        "sub": uid,
        "iat": now,
        "exp": now + datetime.timedelta(seconds=ttl),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, _SECRET_KEY, algorithm=_ALGORITHM)


def require[**P, R](func: Callable[P, Coroutine[Any, Any, R]]) -> Callable[P, Awaitable[R]]:
    @functools.wraps(func)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        token = _extract_bearer_token(quart.request)
        try:
            claims = verify(token)
        except jwt.PyJWTError as exc:
            raise base.ASFQuartException(f"Invalid Bearer JWT: {exc}", errorcode=401) from exc

        quart.g.jwt_claims = claims
        return await func(*args, **kwargs)

    return wrapper


def unverified_header_and_payload(jwt_value: str) -> dict[str, Any]:
    header = jwt.get_unverified_header(jwt_value)

    try:
        payload = jwt.decode(jwt_value, options={"verify_signature": False})
    except jwt.PyJWTError as e:
        raise RuntimeError(f"Failed to decode JWT: {e}") from e

    return {"header": header, "payload": payload}


def verify(token: str) -> dict[str, Any]:
    return jwt.decode(token, _SECRET_KEY, algorithms=[_ALGORITHM])


def _extract_bearer_token(request: quart.Request) -> str:
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise base.ASFQuartException("Bearer JWT missing", errorcode=401)
    return token
