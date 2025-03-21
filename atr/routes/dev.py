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


import asfquart as asfquart
import asfquart.auth as auth
import asfquart.base as base
import asfquart.session as session
import quart

import atr.db as db
import atr.db.models as models
import atr.routes as routes

if asfquart.APP is ...:
    raise RuntimeError("APP is not set")


@routes.app_route("/dev/send-email", methods=["GET", "POST"])
@auth.require(auth.Requirements.committer)
async def dev_email_send() -> quart.ResponseReturnValue:
    """Simple endpoint for testing email functionality."""
    web_session = await session.read()
    if web_session is None:
        raise base.ASFQuartException("Not authenticated", errorcode=401)
    asf_id = web_session.uid

    if quart.request.method == "POST":
        form = await routes.get_form(quart.request)

        email = form.get("email_recipient", "")
        name = form.get("artifact_name", "")
        token = form.get("token", "")

        if not email:
            return await quart.render_template(
                "dev-send-email.html",
                asf_id=asf_id,
                error="Email recipient is required",
            )

        if not name:
            return await quart.render_template(
                "dev-send-email.html",
                asf_id=asf_id,
                error="Artifact name is required",
            )

        # Create a task for mail testing
        async with db.create_async_db_session() as db_session:
            async with db_session.begin():
                task = models.Task(
                    status=models.TaskStatus.QUEUED,
                    task_type="mailtest_send",
                    task_args=[name, email, token],
                )
                db_session.add(task)
                # Flush to get the task ID
                await db_session.flush()

        return await quart.render_template(
            "dev-send-email.html",
            asf_id=asf_id,
            success=True,
            message=f"Email task queued with ID {task.id}. It will be processed by a worker.",
            email_recipient=email,
            artifact_name=name,
            token=token,
        )

    return await quart.render_template("dev-send-email.html", asf_id=asf_id)
