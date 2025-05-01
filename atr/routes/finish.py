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
import pathlib
from typing import Final

import aiofiles.os
import quart
import werkzeug.wrappers.response as response
import wtforms

import atr.db.models as models
import atr.revision as revision
import atr.routes as routes
import atr.routes.root as root
import atr.util as util

_LOGGER: Final = logging.getLogger(__name__)


class MoveFileForm(util.QuartFormTyped):
    """Form for moving a file within a preview revision."""

    source_file = wtforms.SelectField("File to move", choices=[], validators=[wtforms.validators.InputRequired()])
    target_directory = wtforms.SelectField(
        "Target directory", choices=[], validators=[wtforms.validators.InputRequired()]
    )
    submit = wtforms.SubmitField("Move file")

    def validate_target_directory(self, field: wtforms.Field) -> None:
        # This validation runs only if both fields have data
        if self.source_file.data and field.data:
            source_path = pathlib.Path(self.source_file.data)
            target_dir = pathlib.Path(field.data)
            if source_path.parent == target_dir:
                raise wtforms.validators.ValidationError("Target directory cannot be the same as the source directory.")


@routes.committer("/finish/<project_name>/<version_name>", methods=["GET", "POST"])
async def selected(session: routes.CommitterSession, project_name: str, version_name: str) -> response.Response | str:
    """Finish a release preview."""
    await session.check_access(project_name)

    release = await session.release(project_name, version_name, phase=models.ReleasePhase.RELEASE_PREVIEW)
    current_revision_dir = util.release_directory(release)
    file_paths_rel: list[pathlib.Path] = []
    unique_dirs: set[pathlib.Path] = {pathlib.Path(".")}

    try:
        for path in await util.paths_recursive(current_revision_dir):
            file_paths_rel.append(path)
            unique_dirs.add(path.parent)
    except FileNotFoundError:
        await quart.flash("Preview revision directory not found.", "error")
        return await session.redirect(root.index)

    form = await MoveFileForm.create_form(data=await quart.request.form if (quart.request.method == "POST") else None)

    # Populate choices dynamically for both GET and POST
    form.source_file.choices = sorted([(str(p), str(p)) for p in file_paths_rel])
    form.target_directory.choices = sorted([(str(d), str(d)) for d in unique_dirs])
    can_move = len(unique_dirs) > 1

    if (quart.request.method == "POST") and can_move:
        match r := await _move_file(form, session, project_name, version_name):
            case None:
                pass
            case response.Response():
                return r

    return await quart.render_template(
        "finish-selected.html",
        asf_id=session.uid,
        server_domain=session.host,
        release=release,
        file_paths=sorted(file_paths_rel),
        form=form,
        can_move=can_move,
    )


async def _move_file(
    form: MoveFileForm, session: routes.CommitterSession, project_name: str, version_name: str
) -> response.Response | None:
    if await form.validate_on_submit():
        source_file_rel = pathlib.Path(form.source_file.data)
        target_dir_rel = pathlib.Path(form.target_directory.data)

        try:
            async with revision.create_and_manage(project_name, version_name, session.uid, preview=True) as (
                new_revision_dir,
                new_revision_name,
            ):
                source_path_in_new = new_revision_dir / source_file_rel
                target_path_in_new = new_revision_dir / target_dir_rel / source_file_rel.name

                if await aiofiles.os.path.exists(target_path_in_new):
                    await quart.flash(
                        f"File '{source_file_rel.name}' already exists in '{target_dir_rel}' in new revision.",
                        "error",
                    )
                    return await session.redirect(selected, project_name=project_name, version_name=version_name)

                _LOGGER.info(f"Moving {source_path_in_new} to {target_path_in_new} in new revision {new_revision_name}")
                await aiofiles.os.rename(source_path_in_new, target_path_in_new)

            await quart.flash(
                f"File '{source_file_rel.name}' moved successfully to '{target_dir_rel}' in new revision.", "success"
            )
            return await session.redirect(selected, project_name=project_name, version_name=version_name)

        except FileNotFoundError:
            _LOGGER.exception("File not found during move operation in new revision")
            await quart.flash("Error: Source file not found during move operation.", "error")
        except OSError as e:
            _LOGGER.exception("Error moving file in new revision")
            await quart.flash(f"Error moving file: {e}", "error")
        except Exception as e:
            _LOGGER.exception("Unexpected error during file move")
            await quart.flash(f"An unexpected error occurred: {e!s}", "error")
            return await session.redirect(selected, project_name=project_name, version_name=version_name)
    else:
        for field, errors in form.errors.items():
            field_label = getattr(getattr(form, field, None), "label", None)
            label_text = field_label.text if field_label else field.replace("_", " ").title()
            for error in errors:
                await quart.flash(f"{label_text}: {error}", "warning")
    return None
