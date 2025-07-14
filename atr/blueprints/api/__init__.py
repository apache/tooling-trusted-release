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

import sys
from typing import Any

import asfquart.base as base
import pydantic
import quart
import quart.blueprints as blueprints
import quart_schema
import werkzeug.exceptions as exceptions

BLUEPRINT = quart.Blueprint("api_blueprint", __name__, url_prefix="/api")


def _exempt_blueprint(app: base.QuartApp) -> None:
    csrf = app.extensions.get("csrf")
    if csrf is not None:
        csrf.exempt(BLUEPRINT)


@BLUEPRINT.errorhandler(base.ASFQuartException)
async def _handle_asfquart_exception(err: base.ASFQuartException) -> tuple[quart.Response, int]:
    status = getattr(err, "errorcode", 500)
    return _json_error(str(err), status)


@BLUEPRINT.errorhandler(Exception)
async def _handle_generic_exception(err: Exception) -> tuple[quart.Response, int]:
    return _json_error(str(err), 500)


@BLUEPRINT.errorhandler(exceptions.HTTPException)
async def _handle_http_exception(err: exceptions.HTTPException) -> tuple[quart.Response, int]:
    return _json_error(err.description or err.name, err.code)


@BLUEPRINT.errorhandler(exceptions.NotFound)
async def _handle_not_found(err: exceptions.NotFound) -> tuple[quart.Response, int]:
    return _json_error(err.description or err.name, 404)


@BLUEPRINT.errorhandler(quart_schema.RequestSchemaValidationError)
async def _handle_request_validation(err: quart_schema.RequestSchemaValidationError) -> tuple[quart.Response, int]:
    if not isinstance(err.validation_error, pydantic.ValidationError):
        raise err.validation_error
    verr: pydantic.ValidationError = err.validation_error
    return _json_error("Input validation failed", 400, {"validation_details": verr.errors()})


def _json_error(
    message: str, status_code: int | None, extra: dict[str, Any] | None = None
) -> tuple[quart.Response, int]:
    payload = {"error": message}
    show_traceback = False
    if show_traceback:
        import traceback

        traceback_str = "".join(traceback.format_exception(*sys.exc_info()))
        payload["traceback"] = traceback_str
    if extra is not None:
        payload.update(extra)
    return quart.jsonify(payload), status_code or 500


@BLUEPRINT.record_once
def _setup(state: blueprints.BlueprintSetupState) -> None:
    if isinstance(state.app, base.QuartApp):
        _exempt_blueprint(state.app)
