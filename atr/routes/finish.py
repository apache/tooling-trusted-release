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
import werkzeug.datastructures as datastructures
import werkzeug.wrappers.response as response
import wtforms
import wtforms.fields as fields

import atr.db as db
import atr.db.models as models
import atr.revision as revision
import atr.routes as routes
import atr.routes.root as root
import atr.template as template
import atr.util as util

SPECIAL_SUFFIXES: Final[frozenset[str]] = frozenset({".asc", ".sha256", ".sha512"})

_LOGGER: Final = logging.getLogger(__name__)


class DeleteEmptyDirectoryForm(util.QuartFormTyped):
    """Form for deleting an empty directory within a preview revision."""

    directory_to_delete = wtforms.SelectField(
        "Directory to delete", choices=[], validators=[wtforms.validators.DataRequired()]
    )
    submit = wtforms.SubmitField("Delete directory")


class MoveFileForm(util.QuartFormTyped):
    """Form for moving one or more files within a preview revision."""

    source_files = wtforms.SelectMultipleField(
        "Files to move",
        choices=[],
        validators=[wtforms.validators.DataRequired(message="Please select at least one file to move.")],
    )
    target_directory = wtforms.SelectField(
        "Target directory", choices=[], validators=[wtforms.validators.DataRequired()], validate_choice=False
    )
    submit = wtforms.SubmitField("Move file")

    def validate_source_files(self, field: fields.SelectMultipleField) -> None:
        if not field.data or len(field.data) == 0:
            raise wtforms.validators.ValidationError("Please select at least one file to move.")

    def validate_target_directory(self, field: wtforms.Field) -> None:
        # This validation runs only if both fields have data
        if self.source_files.data and field.data:
            source_paths = [pathlib.Path(sf) for sf in self.source_files.data]
            target_dir = pathlib.Path(field.data)
            for source_path in source_paths:
                if source_path.parent == target_dir:
                    raise wtforms.validators.ValidationError(
                        f"Target directory cannot be the same as the source directory for {source_path.name}."
                    )


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
    delete_dir_form = await DeleteEmptyDirectoryForm.create_form(
        data=formdata if (formdata and formdata.get("form_action") == "delete_empty_dir") else None
    )

    # Populate choices dynamically for both GET and POST
    move_form.source_files.choices = sorted([(str(p), str(p)) for p in source_files_rel])
    move_form.target_directory.choices = sorted([(str(d), str(d)) for d in target_dirs])
    can_move = (len(target_dirs) > 1) and (len(source_files_rel) > 0)

    empty_deletable_dirs: list[pathlib.Path] = []
    if latest_revision_dir.exists():
        for d_rel in target_dirs:
            if d_rel == pathlib.Path("."):
                # Disallow deletion of the root directory
                continue
            d_full = latest_revision_dir / d_rel
            if await aiofiles.os.path.isdir(d_full) and not await aiofiles.os.listdir(d_full):
                empty_deletable_dirs.append(d_rel)
    delete_dir_form.directory_to_delete.choices = sorted([(str(p), str(p)) for p in empty_deletable_dirs])

    if formdata:
        result = await _process_formdata(
            formdata, session, project_name, version_name, move_form, delete_dir_form, can_move
        )
        if result is not None:
            return result

    # resp = await quart.current_app.make_response(template_rendered)
    # resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    # resp.headers["Pragma"] = "no-cache"
    # resp.headers["Expires"] = "0"
    # return resp
    return await template.render(
        "finish-selected.html",
        asf_id=session.uid,
        server_domain=session.app_host,
        release=release,
        source_files=sorted(source_files_rel),
        form=move_form,
        delete_dir_form=delete_dir_form,
        user_ssh_keys=user_ssh_keys,
        target_dirs=sorted(list(target_dirs)),
        max_files_to_show=10,
    )


async def _process_formdata(
    formdata: datastructures.MultiDict,
    session: routes.CommitterSession,
    project_name: str,
    version_name: str,
    move_form: MoveFileForm,
    delete_dir_form: DeleteEmptyDirectoryForm,
    can_move: bool,
) -> tuple[quart_response.Response, int] | response.Response | str | None:
    form_action = formdata.get("form_action")

    if (
        (quart.request.method == "POST")
        and ("source_files" in formdata)
        and ("target_directory" in formdata)
        and (not form_action)
    ):
        source_files_data = formdata.getlist("source_files")
        target_dir_data = formdata.get("target_directory")
        wants_json = quart.request.accept_mimetypes.best_match(["application/json", "text/html"]) == "application/json"

        if not source_files_data or not target_dir_data:
            return await _respond(
                session,
                project_name,
                version_name,
                wants_json,
                False,
                "Missing source file(s) or target directory.",
                400,
            )

        source_files_rel = [pathlib.Path(sf) for sf in source_files_data]
        target_dir_rel = pathlib.Path(target_dir_data)

        if not source_files_rel:
            return await _respond(
                session, project_name, version_name, wants_json, False, "No source files selected.", 400
            )
        return await _move_file_to_revision(
            source_files_rel, target_dir_rel, session, project_name, version_name, wants_json
        )

    elif form_action == "delete_empty_dir":
        wants_json = quart.request.accept_mimetypes.best_match(["application/json", "text/html"]) == "application/json"
        if await delete_dir_form.validate_on_submit():
            dir_to_delete_str = delete_dir_form.directory_to_delete.data
            return await _delete_empty_dir_action(
                pathlib.Path(dir_to_delete_str), session, project_name, version_name, wants_json
            )
        elif wants_json:
            error_messages = []
            for field_name_str, error_list in delete_dir_form.errors.items():
                field_obj = getattr(delete_dir_form, field_name_str, None)
                label_text = field_name_str.replace("_", " ").title()
                if field_obj and hasattr(field_obj, "label") and field_obj.label:
                    label_text = field_obj.label.text
                error_messages.append(f"{label_text}: {', '.join(error_list)}")
            error_msg = "; ".join(error_messages)
            return await _respond(session, project_name, version_name, True, False, error_msg or "Invalid input.", 400)

    elif ((form_action != "create_dir") or (form_action is None)) and can_move:
        return await _move_file(move_form, session, project_name, version_name)
    return None


async def _move_file(
    form: MoveFileForm,
    session: routes.CommitterSession,
    project_name: str,
    version_name: str,
) -> tuple[quart_response.Response, int] | response.Response | None:
    wants_json = "application/json" in quart.request.headers.get("Accept", "")

    if await form.validate_on_submit():
        source_files_rel_str_list = form.source_files.data
        target_dir_rel_str = form.target_directory.data
        if not source_files_rel_str_list or not target_dir_rel_str:
            return await _respond(
                session,
                project_name,
                version_name,
                wants_json,
                False,
                "Source file(s) or target directory missing.",
                400,
            )

        source_files_rel = [pathlib.Path(sf_str) for sf_str in source_files_rel_str_list]
        target_dir_rel = pathlib.Path(target_dir_rel_str)
        return await _move_file_to_revision(
            source_files_rel, target_dir_rel, session, project_name, version_name, wants_json
        )
    else:
        if wants_json:
            error_messages = []
            for field_name, field_errors in form.errors.items():
                field_object = getattr(form, field_name, None)
                label_text = field_name.replace("_", " ").title()
                if field_object and hasattr(field_object, "label") and field_object.label:
                    label_text = field_object.label.text
                error_messages.append(f"{label_text}: {', '.join(field_errors)}")
            error_string = "; ".join(error_messages)
            return await _respond(session, project_name, version_name, True, False, error_string, 400)
        else:
            for field_name, field_errors in form.errors.items():
                field_object = getattr(form, field_name, None)
                label_text = field_name.replace("_", " ").title()
                if field_object and hasattr(field_object, "label") and field_object.label:
                    label_text = field_object.label.text
                for error_message_text in field_errors:
                    await quart.flash(f"{label_text}: {error_message_text}", "warning")
            return None


async def _move_file_to_revision(
    source_files_rel: list[pathlib.Path],
    target_dir_rel: pathlib.Path,
    session: routes.CommitterSession,
    project_name: str,
    version_name: str,
    wants_json: bool,
) -> tuple[quart_response.Response, int] | response.Response:
    try:
        description = "File move through web interface"
        moved_files_names: list[str] = []
        skipped_files_names: list[str] = []

        async with revision.create_and_manage(
            project_name, version_name, session.uid, description=description
        ) as creating:
            await _setup_revision(
                source_files_rel,
                target_dir_rel,
                creating,
                moved_files_names,
                skipped_files_names,
            )

        if creating.failed is not None:
            return await _respond(
                session,
                project_name,
                version_name,
                wants_json,
                False,
                str(creating.failed),
                409,
            )

        response_messages = []
        if moved_files_names:
            response_messages.append(f"Moved {', '.join(moved_files_names)}")
        if skipped_files_names:
            response_messages.append(f"Skipped {', '.join(skipped_files_names)} (already in target directory)")

        if not response_messages:
            if not source_files_rel:
                return await _respond(
                    session, project_name, version_name, wants_json, False, "No source files specified for move.", 400
                )
            msg = f"No files were moved. {', '.join(skipped_files_names)} already in '{target_dir_rel}'."
            return await _respond(session, project_name, version_name, wants_json, True, msg, 200)

        final_msg = ". ".join(response_messages) + "."
        return await _respond(session, project_name, version_name, wants_json, True, final_msg, 200)

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
        return await _respond(session, project_name, version_name, wants_json, False, f"ERROR: {e!s}", 500)


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


async def _setup_revision(
    source_files_rel: list[pathlib.Path],
    target_dir_rel: pathlib.Path,
    creating: revision.Creating,
    moved_files_names: list[str],
    skipped_files_names: list[str],
) -> None:
    target_path = creating.interim_path / target_dir_rel
    try:
        target_path.resolve().relative_to(creating.interim_path.resolve())
    except ValueError:
        # Path traversal detected
        raise revision.FailedError("Paths must be restricted to the release directory")

    if not await aiofiles.os.path.exists(target_path):
        for part in target_path.parts:
            # TODO: This .prefix check could include some existing directory segment
            if part.startswith("."):
                raise revision.FailedError("Segments must not start with '.'")
            if ".." in part:
                raise revision.FailedError("Segments must not contain '..'")

        try:
            await aiofiles.os.makedirs(target_path)
        except OSError:
            raise revision.FailedError("Failed to create target directory")
    elif not await aiofiles.os.path.isdir(target_path):
        raise revision.FailedError("Target path is not a directory")

    for source_file_rel in source_files_rel:
        await _setup_revision_item(
            source_file_rel, target_dir_rel, creating, moved_files_names, skipped_files_names, target_path
        )


async def _setup_revision_item(
    source_file_rel: pathlib.Path,
    target_dir_rel: pathlib.Path,
    creating: revision.Creating,
    moved_files_names: list[str],
    skipped_files_names: list[str],
    target_path: pathlib.Path,
) -> None:
    if source_file_rel.parent == target_dir_rel:
        skipped_files_names.append(source_file_rel.name)
        return

    full_source_item_path = creating.interim_path / source_file_rel

    if await aiofiles.os.path.isdir(full_source_item_path):
        if (target_dir_rel == source_file_rel) or (creating.interim_path / target_dir_rel).resolve().is_relative_to(
            full_source_item_path.resolve()
        ):
            raise revision.FailedError("Cannot move a directory into itself or a subdirectory of itself")

        final_target_for_item = target_path / source_file_rel.name
        if await aiofiles.os.path.exists(final_target_for_item):
            raise revision.FailedError("Target name already exists")

        await aiofiles.os.rename(full_source_item_path, final_target_for_item)
        moved_files_names.append(source_file_rel.name)
    else:
        related_files = _related_files(source_file_rel)
        bundle = [f for f in related_files if await aiofiles.os.path.exists(creating.interim_path / f)]
        for f_check in bundle:
            if await aiofiles.os.path.isdir(creating.interim_path / f_check):
                raise revision.FailedError("A related 'file' is actually a directory")

        collisions = [f.name for f in bundle if await aiofiles.os.path.exists(target_path / f.name)]
        if collisions:
            raise revision.FailedError("A related file already exists in the target directory")

        for f in bundle:
            await aiofiles.os.rename(creating.interim_path / f, target_path / f.name)
            if f == source_file_rel:
                moved_files_names.append(f.name)


async def _sources_and_targets(latest_revision_dir: pathlib.Path) -> tuple[list[pathlib.Path], set[pathlib.Path]]:
    source_items_rel: list[pathlib.Path] = []
    target_dirs: set[pathlib.Path] = {pathlib.Path(".")}

    async for item_rel_path in util.paths_recursive_all(latest_revision_dir):
        current_parent = item_rel_path.parent
        source_items_rel.append(item_rel_path)

        while True:
            target_dirs.add(current_parent)
            if current_parent == pathlib.Path("."):
                break
            current_parent = current_parent.parent

        item_abs_path = latest_revision_dir / item_rel_path
        if await aiofiles.os.path.isfile(item_abs_path):
            pass
        elif await aiofiles.os.path.isdir(item_abs_path):
            target_dirs.add(item_rel_path)

    return source_items_rel, target_dirs


async def _delete_empty_dir_action(
    dir_to_delete_rel: pathlib.Path,
    session: routes.CommitterSession,
    project_name: str,
    version_name: str,
    wants_json: bool,
) -> tuple[quart_response.Response, int] | response.Response:
    try:
        description = f"Delete empty directory {dir_to_delete_rel} via web interface"
        async with revision.create_and_manage(
            project_name, version_name, session.uid, description=description
        ) as creating:
            path_to_remove = creating.interim_path / dir_to_delete_rel
            path_to_remove.resolve().relative_to(creating.interim_path.resolve())
            if not await aiofiles.os.path.isdir(path_to_remove):
                raise revision.FailedError(f"Path '{dir_to_delete_rel}' is not a directory.")
            if await aiofiles.os.listdir(path_to_remove):
                raise revision.FailedError(f"Directory '{dir_to_delete_rel}' is not empty.")
            await aiofiles.os.rmdir(path_to_remove)

    except Exception:
        _LOGGER.exception(f"Unexpected error deleting directory {dir_to_delete_rel} for {project_name}/{version_name}")
        return await _respond(
            session, project_name, version_name, wants_json, False, "An unexpected error occurred.", 500
        )

    if creating.failed is not None:
        return await _respond(session, project_name, version_name, wants_json, False, str(creating.failed), 400)
    return await _respond(
        session, project_name, version_name, wants_json, True, f"Deleted empty directory '{dir_to_delete_rel}'.", 200
    )
