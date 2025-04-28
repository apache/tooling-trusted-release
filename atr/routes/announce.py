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

import logging

import aiofiles.os
import aioshutil
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.routes as routes

# TODO: Improve upon the routes_release pattern
import atr.routes.release as routes_release
import atr.util as util


class AnnounceForm(util.QuartFormTyped):
    """Form for announcing a release preview."""

    preview_name = wtforms.StringField(
        "Preview name", validators=[wtforms.validators.InputRequired("Preview name is required")]
    )
    preview_revision = wtforms.StringField(
        "Preview revision", validators=[wtforms.validators.InputRequired("Preview revision is required")]
    )
    confirm_announce = wtforms.BooleanField(
        "Confirmation",
        validators=[wtforms.validators.DataRequired("You must confirm to proceed with announcement")],
    )
    submit = wtforms.SubmitField("Announce release")


class DeleteForm(util.QuartFormTyped):
    """Form for deleting a release preview."""

    preview_name = wtforms.StringField(
        "Preview name", validators=[wtforms.validators.InputRequired("Preview name is required")]
    )
    confirm_delete = wtforms.StringField(
        "Confirmation",
        validators=[
            wtforms.validators.InputRequired("Confirmation is required"),
            wtforms.validators.Regexp("^DELETE$", message="Please type DELETE to confirm"),
        ],
    )
    submit = wtforms.SubmitField("Delete preview")


@routes.committer("/announce/<project_name>/<version_name>")
async def selected(session: routes.CommitterSession, project_name: str, version_name: str) -> str | response.Response:
    """Allow the user to announce a release preview."""
    await session.check_access(project_name)

    announce_form = await AnnounceForm.create_form()
    release = await session.release(project_name, version_name, phase=models.ReleasePhase.RELEASE_PREVIEW)
    return await quart.render_template("preview-announce-release.html", release=release, announce_form=announce_form)


@routes.committer("/announce/<project_name>/<version_name>", methods=["POST"])
async def selected_post(
    session: routes.CommitterSession, project_name: str, version_name: str
) -> str | response.Response:
    """Allow the user to announce a release preview."""
    await session.check_access(project_name)

    # Get user's preview releases
    async with db.session() as data:
        releases = await data.release(
            stage=models.ReleaseStage.RELEASE,
            phase=models.ReleasePhase.RELEASE_PREVIEW,
            _committee=True,
        ).all()
    user_previews = session.only_user_releases(releases)

    # Create the forms
    announce_form = await AnnounceForm.create_form(
        data=await quart.request.form if (quart.request.method == "POST") else None
    )
    delete_form = await DeleteForm.create_form()

    if (quart.request.method == "POST") and (await announce_form.validate_on_submit()):
        try:
            _preview_name, project_name, version_name, _preview_revision = _announce_form_validate(announce_form)
        except ValueError as e:
            return await session.redirect(selected, error=str(e), project_name=project_name, version_name=version_name)

        # Check that the user has access to the project
        async with db.session() as data:
            try:
                # Get the release
                release = await session.release(
                    project_name, version_name, phase=models.ReleasePhase.RELEASE_PREVIEW, data=data
                )

                if release.revision is None:
                    # Impossible, but to satisfy the type checkers
                    return await session.redirect(
                        selected,
                        error="This release does not have a revision",
                        project_name=project_name,
                        version_name=version_name,
                    )

                source_base = util.release_directory_base(release)
                source = str(source_base / release.revision)

                # Update the database
                release.phase = models.ReleasePhase.RELEASE
                release.revision = None

                # This must come after updating the release object
                target = str(util.release_directory(release))
                if await aiofiles.os.path.exists(target):
                    return await session.redirect(
                        selected, error="Release already exists", project_name=project_name, version_name=version_name
                    )

                await data.commit()

                # Move the revision directory
                await aioshutil.move(source, target)

                # Remove the rest of the preview history
                # This must come after moving the revision directory, otherwise it will be removed too
                await aioshutil.rmtree(str(source_base))  # type: ignore[call-arg]

                routes_release_releases = routes_release.releases  # type: ignore[has-type]
                return await session.redirect(routes_release_releases, success="Preview successfully announced")

            except Exception as e:
                logging.exception("Error announcing preview:")
                return await session.redirect(
                    selected,
                    error=f"Error announcing preview: {e!s}",
                    project_name=project_name,
                    version_name=version_name,
                )

    return await quart.render_template(
        "preview-announce.html",
        previews=user_previews,
        announce_form=announce_form,
        delete_form=delete_form,
    )


def _announce_form_validate(announce_form: AnnounceForm) -> tuple[str, str, str, str]:
    preview_name = announce_form.preview_name.data
    if not preview_name:
        raise ValueError("Missing required parameters")

    # Extract project name and version
    try:
        project_name, version_name = preview_name.rsplit("-", 1)
    except ValueError:
        raise ValueError("Invalid preview name format")

    preview_revision = announce_form.preview_revision.data
    if not preview_revision:
        raise ValueError("Missing required parameters")

    return preview_name, project_name, version_name, preview_revision
