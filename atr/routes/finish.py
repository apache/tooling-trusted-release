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
import quart.wrappers.response as quart_response
import werkzeug.wrappers.response as response
import wtforms

import atr.db as db
import atr.db.models as models
import atr.revision as revision
import atr.routes as routes
import atr.routes.root as root
import atr.util as util

SPECIAL_SUFFIXES: Final[frozenset[str]] = frozenset({".asc", ".sha256", ".sha512"})

_LOGGER: Final = logging.getLogger(__name__)


class CreateDirectoryForm(util.QuartFormTyped):
    """Form for creating a new directory within a preview revision."""

    new_directory_name = wtforms.StringField(
        "New directory name",
        validators=[
            wtforms.validators.InputRequired(),
            wtforms.validators.Regexp(
                r"^(?!.*\.\.)(?!^\.$)(?!^/)(?!.*/$)[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*$",
                message="Invalid characters or structure. Use a-z, 0-9, _, -."
                " No leading or trailing slashes, and no dots. No '..' segments.",
            ),
        ],
    )
    submit = wtforms.SubmitField("Create directory")


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
async def selected(
    session: routes.CommitterSession, project_name: str, version_name: str
) -> tuple[quart_response.Response, int] | response.Response | str:
    """Finish a release preview."""
    await session.check_access(project_name)

    async with db.session() as data:
        release = await session.release(
            project_name, version_name, phase=models.ReleasePhase.RELEASE_PREVIEW, data=data
        )
        user_ssh_keys = await data.ssh_key(asf_uid=session.uid).all()

    latest_revision_dir = util.release_directory(release)
    try:
        source_files_rel, target_dirs = await _sources_and_targets(latest_revision_dir)
    except FileNotFoundError:
        await quart.flash("Preview revision directory not found.", "error")
        return await session.redirect(root.index)

    formdata = None
    if quart.request.method == "POST":
        formdata = await quart.request.form

    move_form = await MoveFileForm.create_form(
        data=formdata if (formdata and formdata.get("form_action") != "create_dir") else None
    )
    create_dir_form = await CreateDirectoryForm.create_form(
        data=formdata if (formdata and formdata.get("form_action") == "create_dir") else None
    )

    # Populate choices dynamically for both GET and POST
    move_form.source_file.choices = sorted([(str(p), str(p)) for p in source_files_rel])
    move_form.target_directory.choices = sorted([(str(d), str(d)) for d in target_dirs])
    can_move = (len(target_dirs) > 1) and (len(source_files_rel) > 0)

    if formdata:
        form_action = formdata.get("form_action")
        if form_action == "create_dir":
            if await create_dir_form.validate_on_submit():
                new_dir_name = create_dir_form.new_directory_name.data
                if new_dir_name:
                    return await _create_directory_in_revision(
                        pathlib.Path(new_dir_name),
                        session,
                        project_name,
                        version_name,
                        quart.request.accept_mimetypes.best_match(["application/json", "text/html"])
                        == "application/json",
                    )
        elif (form_action != "create_dir") and can_move:
            move_result = await _move_file(move_form, session, project_name, version_name)
            if move_result is not None:
                return move_result

    # resp = await quart.current_app.make_response(template_rendered)
    # resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    # resp.headers["Pragma"] = "no-cache"
    # resp.headers["Expires"] = "0"
    # return resp
    return await quart.render_template(
        "finish-selected.html",
        asf_id=session.uid,
        server_domain=session.app_host,
        release=release,
        source_files=sorted(source_files_rel),
        form=move_form,
        create_dir_form=create_dir_form,
        can_move=can_move,
        user_ssh_keys=user_ssh_keys,
        target_dirs=sorted(list(target_dirs)),
    )


async def _respond(
    session: routes.CommitterSession,
    project_name: str,
    version_name: str,
    wants_json: bool,
    ok: bool,
    msg: str,
    http_status: int = 200,
) -> tuple[quart_response.Response, int] | response.Response:
    """Helper to respond with JSON or flash message and redirect."""
    if wants_json:
        return quart.jsonify(ok=ok, message=msg), http_status
    await quart.flash(msg, "success" if ok else "error")
    return await session.redirect(selected, project_name=project_name, version_name=version_name)


async def _create_directory_in_revision(
    new_dir_rel: pathlib.Path,
    session: routes.CommitterSession,
    project_name: str,
    version_name: str,
    wants_json: bool,
) -> tuple[quart_response.Response, int] | response.Response:
    try:
        description = "Directory creation through web interface"
        async with revision.create_and_manage(
            project_name, version_name, session.uid, description=description
        ) as creating:
            target_path = creating.interim_path / new_dir_rel
            # Path traversal check
            try:
                resolved_target_path = target_path.resolve()
                resolved_target_path.relative_to(creating.interim_path.resolve())
                await aiofiles.os.makedirs(target_path, exist_ok=False)
            except ValueError:
                creating.failed = True
                # Path traversal attempt detected
                return await _respond(
                    session, project_name, version_name, wants_json, False, "Invalid directory path.", 400
                )
            except FileExistsError:
                creating.failed = True
                return await _respond(
                    session,
                    project_name,
                    version_name,
                    wants_json,
                    False,
                    f"Directory or file '{new_dir_rel}' already exists.",
                    400,
                )
        return await _respond(
            session,
            project_name,
            version_name,
            wants_json,
            True,
            f"Created directory '{new_dir_rel}'.",
            201 if wants_json else 200,
        )
    except OSError as e:
        _LOGGER.exception("Error creating directory in new revision")
        return await _respond(
            session, project_name, version_name, wants_json, False, f"Error creating directory: {e}", 500
        )
    except Exception as e:
        _LOGGER.exception("Unexpected error during directory creation")
        return await _respond(
            session, project_name, version_name, wants_json, False, f"An unexpected error occurred: {e!s}", 500
        )


async def _move_file(
    form: MoveFileForm, session: routes.CommitterSession, project_name: str, version_name: str
) -> tuple[quart_response.Response, int] | response.Response | None:
    wants_json = "application/json" in quart.request.headers.get("Accept", "")
    if await form.validate_on_submit():
        source_file_rel = pathlib.Path(form.source_file.data)
        target_dir_rel = pathlib.Path(form.target_directory.data)
        return await _move_file_to_revision(
            source_file_rel, target_dir_rel, session, project_name, version_name, wants_json
        )
    else:
        if wants_json:
            error_messages = []
            for field_name, field_errors in form.errors.items():
                field_object = getattr(form, field_name, None)
                label_object = getattr(field_object, "label", None)
                label_text = label_object.text if label_object else field_name.replace("_", " ").title()
                error_messages.append(f"{label_text}: {', '.join(field_errors)}")
            error_string = "; ".join(error_messages)
            return await _respond(session, project_name, version_name, True, False, error_string, 400)
        else:
            for field_name, field_errors in form.errors.items():
                field_object = getattr(form, field_name, None)
                label_object = getattr(field_object, "label", None)
                label_text = label_object.text if label_object else field_name.replace("_", " ").title()
                for error_message_text in field_errors:
                    await quart.flash(f"{label_text}: {error_message_text}", "warning")
            return None


async def _move_file_to_revision(
    source_file_rel: pathlib.Path,
    target_dir_rel: pathlib.Path,
    session: routes.CommitterSession,
    project_name: str,
    version_name: str,
    wants_json: bool,
) -> tuple[quart_response.Response, int] | response.Response:
    try:
        description = "File move through web interface"
        async with revision.create_and_manage(
            project_name, version_name, session.uid, description=description
        ) as creating:
            related_files = _related_files(source_file_rel)
            bundle = [f for f in related_files if await aiofiles.os.path.exists(creating.interim_path / f)]
            collisions = [
                f.name for f in bundle if await aiofiles.os.path.exists(creating.interim_path / target_dir_rel / f.name)
            ]
            if collisions:
                # Remove the temporary directory, and do not create or commit a new revision
                # (But also do not raise an exception)
                creating.failed = True
                msg = f"Files already exist in '{target_dir_rel}': {', '.join(collisions)}"
                return await _respond(session, project_name, version_name, wants_json, False, msg, 400)

            for f in bundle:
                await aiofiles.os.rename(creating.interim_path / f, creating.interim_path / target_dir_rel / f.name)

        return await _respond(
            session, project_name, version_name, wants_json, True, f"Moved {', '.join(f.name for f in bundle)}", 200
        )

    except FileNotFoundError:
        _LOGGER.exception("File not found during move operation in new revision")
        return await _respond(
            session,
            project_name,
            version_name,
            wants_json,
            False,
            "Error: Source file not found during move operation.",
            400,
        )
    except OSError as e:
        _LOGGER.exception("Error moving file in new revision")
        return await _respond(session, project_name, version_name, wants_json, False, f"Error moving file: {e}", 500)
    except Exception as e:
        _LOGGER.exception("Unexpected error during file move")
        return await _respond(
            session, project_name, version_name, wants_json, False, f"An unexpected error occurred: {e!s}", 500
        )


def _related_files(path: pathlib.Path) -> list[pathlib.Path]:
    base_path = path.with_suffix("") if (path.suffix in SPECIAL_SUFFIXES) else path
    parent_dir = base_path.parent
    name_without_ext = base_path.name
    return [
        parent_dir / name_without_ext,
        parent_dir / f"{name_without_ext}.asc",
        parent_dir / f"{name_without_ext}.sha256",
        parent_dir / f"{name_without_ext}.sha512",
    ]


async def _sources_and_targets(latest_revision_dir: pathlib.Path) -> tuple[list[pathlib.Path], set[pathlib.Path]]:
    source_files_rel: list[pathlib.Path] = []
    target_dirs: set[pathlib.Path] = {pathlib.Path(".")}

    async for item_rel_path in util.paths_recursive_all(latest_revision_dir):
        current_parent = item_rel_path.parent
        while True:
            target_dirs.add(current_parent)
            if current_parent == pathlib.Path("."):
                break
            current_parent = current_parent.parent

        item_abs_path = latest_revision_dir / item_rel_path
        if await aiofiles.os.path.isfile(item_abs_path):
            source_files_rel.append(item_rel_path)
        elif await aiofiles.os.path.isdir(item_abs_path):
            target_dirs.add(item_rel_path)

    return source_files_rel, target_dirs
