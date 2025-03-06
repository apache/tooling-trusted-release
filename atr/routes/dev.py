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


from quart import render_template, request
from quart.typing import ResponseReturnValue

from asfquart import APP
from asfquart.auth import Requirements, require
from asfquart.base import ASFQuartException
from asfquart.session import read as session_read
from atr.db import create_async_db_session
from atr.db.models import Task, TaskStatus
from atr.routes import app_route, get_form

if APP is ...:
    raise RuntimeError("APP is not set")


@app_route("/dev/send-email", methods=["GET", "POST"])
@require(Requirements.committer)
async def dev_email_send() -> ResponseReturnValue:
    """Simple endpoint for testing email functionality."""
    session = await session_read()
    if session is None:
        raise ASFQuartException("Not authenticated", errorcode=401)
    asf_id = session.uid

    if request.method == "POST":
        form = await get_form(request)

        email = form.get("email_recipient", "")
        name = form.get("artifact_name", "")
        token = form.get("token", "")

        if not email:
            return await render_template(
                "dev-send-email.html",
                asf_id=asf_id,
                error="Email recipient is required",
            )

        if not name:
            return await render_template(
                "dev-send-email.html",
                asf_id=asf_id,
                error="Artifact name is required",
            )

        # Create a task for mail testing
        async with create_async_db_session() as db_session:
            async with db_session.begin():
                task = Task(
                    status=TaskStatus.QUEUED,
                    task_type="mailtest_send",
                    task_args=[name, email, token],
                )
                db_session.add(task)
                # Flush to get the task ID
                await db_session.flush()

        return await render_template(
            "dev-send-email.html",
            asf_id=asf_id,
            success=True,
            message=f"Email task queued with ID {task.id}. It will be processed by a worker.",
            email_recipient=email,
            artifact_name=name,
            token=token,
        )

    return await render_template("dev-send-email.html", asf_id=asf_id)
