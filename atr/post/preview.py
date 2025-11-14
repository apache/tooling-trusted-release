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

import datetime

import pydantic

import atr.blueprints.post as post
import atr.construct as construct
import atr.form as form
import atr.log as log
import atr.web as web


class AnnouncePreviewForm(form.Form):
    body: str = form.label("Body", widget=form.Widget.TEXTAREA)


class VotePreviewForm(form.Form):
    body: str = form.label("Body", widget=form.Widget.TEXTAREA)
    duration: form.Int = form.label("Vote duration")


@post.committer("/preview/announce/<project_name>/<version_name>")
# Do not add a post.form decorator here because this is requested from JavaScript
# TODO We could perhaps add a parameter to the decorator
async def announce_preview(session: web.Committer, project_name: str, version_name: str) -> web.QuartResponse:
    """Generate a preview of the announcement email body from JavaScript."""

    form_data = await form.quart_request()

    try:
        # Because this is requested from JavaScript, we validate manually
        # Otherwise errors redirect back to a page which does not exist
        validated_form = form.validate(AnnouncePreviewForm, form_data)
        if not isinstance(validated_form, AnnouncePreviewForm):
            raise ValueError("Invalid form data")
    except pydantic.ValidationError as e:
        errors = e.errors()
        error_details = "; ".join([f"{err['loc'][0]}: {err['msg']}" for err in errors])
        return web.TextResponse(f"Error: Invalid preview request: {error_details}", status=400)

    try:
        # Construct options and generate body
        options = construct.AnnounceReleaseOptions(
            asfuid=session.uid,
            fullname=session.fullname,
            project_name=project_name,
            version_name=version_name,
        )
        preview_body = await construct.announce_release_body(validated_form.body, options)

        return web.TextResponse(preview_body)

    except Exception as e:
        log.exception("Error generating announcement preview:")
        return web.TextResponse(f"Error generating preview: {e!s}", status=500)


@post.committer("/preview/vote/<project_name>/<version_name>")
# Do not add a post.form decorator here because this is requested from JavaScript
async def vote_preview(session: web.Committer, project_name: str, version_name: str) -> web.QuartResponse:
    """Generate a preview of the vote email body from JavaScript."""

    form_data = await form.quart_request()

    try:
        # Because this is requested from JavaScript, we validate manually
        # Otherwise errors redirect back to a page which does not exist
        validated_form = form.validate(VotePreviewForm, form_data)
        if not isinstance(validated_form, VotePreviewForm):
            raise ValueError("Invalid form data")
    except pydantic.ValidationError as e:
        errors = e.errors()
        error_details = "; ".join([f"{err['loc'][0]}: {err['msg']}" for err in errors])
        return web.TextResponse(f"Error: Invalid preview request: {error_details}", status=400)

    try:
        vote_end = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=validated_form.duration)
        vote_end_str = vote_end.strftime("%Y-%m-%d %H:%M:%S UTC")

        options = construct.StartVoteOptions(
            asfuid=session.uid,
            fullname=session.fullname,
            project_name=project_name,
            version_name=version_name,
            vote_duration=validated_form.duration,
            vote_end=vote_end_str,
        )
        preview_body = await construct.start_vote_body(validated_form.body, options)

        return web.TextResponse(preview_body)

    except Exception as e:
        log.exception("Error generating vote preview:")
        return web.TextResponse(f"Error generating preview: {e!s}", status=500)
