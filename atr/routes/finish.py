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

import dataclasses
import pathlib
from collections.abc import Awaitable, Callable
from typing import Any, Final

import aiofiles.os
import quart
import quart.wrappers.response as quart_response
import werkzeug.datastructures as datastructures
import werkzeug.wrappers.response as response
import wtforms
import wtforms.fields as fields

import atr.analysis as analysis
import atr.db as db
import atr.forms as forms
import atr.log as log
import atr.models.sql as sql
import atr.revision as revision
import atr.routes as routes
import atr.routes.root as root
import atr.template as template
import atr.util as util

SPECIAL_SUFFIXES: Final[frozenset[str]] = frozenset({".asc", ".sha256", ".sha512"})


Respond = Callable[[int, str], Awaitable[tuple[quart_response.Response, int] | response.Response]]


class DeleteEmptyDirectoryForm(forms.Typed):
    """Form for deleting an empty directory within a preview revision."""

    directory_to_delete = wtforms.SelectField(
        "Directory to delete", choices=[], validators=[wtforms.validators.DataRequired()]
    )
    submit_delete_empty_dir = wtforms.SubmitField("Delete directory")


class MoveFileForm(forms.Typed):
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


class RemoveRCTagsForm(forms.Typed):
    submit_remove_rc_tags = wtforms.SubmitField("Remove RC tags")


@dataclasses.dataclass
class ProcessFormDataArgs:
    formdata: datastructures.MultiDict
    session: routes.CommitterSession
    project_name: str
    version_name: str
    move_form: MoveFileForm
    delete_dir_form: DeleteEmptyDirectoryForm
    remove_rc_tags_form: RemoveRCTagsForm
    can_move: bool
    wants_json: bool
    respond: Respond


@dataclasses.dataclass
class RCTagAnalysisResult:
    affected_paths_preview: list[tuple[str, str]]
    affected_count: int
    total_paths: int


@routes.committer("/finish/<project_name>/<version_name>", methods=["GET", "POST"])
async def selected(
    session: routes.CommitterSession, project_name: str, version_name: str
) -> tuple[quart_response.Response, int] | response.Response | str:
    """Finish a release preview."""
    await session.check_access(project_name)

    wants_json = quart.request.accept_mimetypes.best_match(["application/json", "text/html"]) == "application/json"

    async def respond(
        http_status: int,
        msg: str,
    ) -> tuple[quart_response.Response, int] | response.Response:
        """Helper to respond with JSON or flash message and redirect."""
        nonlocal session
        nonlocal project_name
        nonlocal version_name
        nonlocal wants_json

        ok = http_status < 300
        if wants_json:
            return quart.jsonify(ok=ok, message=msg), http_status
        await quart.flash(msg, "success" if ok else "error")
        return await session.redirect(selected, project_name=project_name, version_name=version_name)

    async with db.session() as data:
        release = await session.release(project_name, version_name, phase=sql.ReleasePhase.RELEASE_PREVIEW, data=data)
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
        data=formdata if (formdata and ("submit_delete_empty_dir" in formdata)) else None
    )
    remove_rc_tags_form = await RemoveRCTagsForm.create_form(
        data=formdata if (formdata and ("submit_remove_rc_tags" in formdata)) else None
    )

    # Populate choices dynamically for both GET and POST
    move_form.source_files.choices = sorted([(str(p), str(p)) for p in source_files_rel])
    move_form.target_directory.choices = sorted([(str(d), str(d)) for d in target_dirs])
    can_move = (len(target_dirs) > 1) and (len(source_files_rel) > 0)
    delete_dir_form.directory_to_delete.choices = await _deletable_choices(latest_revision_dir, target_dirs)

    if formdata:
        pfd_args = ProcessFormDataArgs(
            formdata=formdata,
            session=session,
            project_name=project_name,
            version_name=version_name,
            move_form=move_form,
            delete_dir_form=delete_dir_form,
            remove_rc_tags_form=remove_rc_tags_form,
            can_move=can_move,
            wants_json=wants_json,
            respond=respond,
        )
        result = await _submission_process(pfd_args)
        if result is not None:
            return result

    rc_analysis_result = await _analyse_rc_tags(latest_revision_dir)
    return await template.render(
        "finish-selected.html",
        asf_id=session.uid,
        server_domain=session.app_host.split(":", 1)[0],
        server_host=session.app_host,
        release=release,
        source_files=sorted(source_files_rel),
        form=move_form,
        delete_dir_form=delete_dir_form,
        user_ssh_keys=user_ssh_keys,
        target_dirs=sorted(list(target_dirs)),
        max_files_to_show=10,
        remove_rc_tags_form=remove_rc_tags_form,
        rc_affected_paths_preview=rc_analysis_result.affected_paths_preview,
        rc_affected_count=rc_analysis_result.affected_count,
        rc_total_paths=rc_analysis_result.total_paths,
    )


async def _analyse_rc_tags(latest_revision_dir: pathlib.Path) -> RCTagAnalysisResult:
    r = RCTagAnalysisResult(
        affected_paths_preview=[],
        affected_count=0,
        total_paths=0,
    )

    if not latest_revision_dir.exists():
        return r

    async for p_rel in util.paths_recursive_all(latest_revision_dir):
        r.total_paths += 1
        original_path_str = str(p_rel)
        stripped_path_str = str(analysis.candidate_removed(p_rel))
        if original_path_str == stripped_path_str:
            continue
        r.affected_count += 1
        if len(r.affected_paths_preview) >= 5:
            # Can't break here, because we need to update the counts
            continue
        highlighted_preview = analysis.candidate_highlight(p_rel)
        r.affected_paths_preview.append((highlighted_preview, stripped_path_str))

    return r


async def _current_paths(creating: revision.Creating) -> list[pathlib.Path]:
    all_current_paths_interim: list[pathlib.Path] = []
    async for p_rel_interim in util.paths_recursive_all(creating.interim_path):
        all_current_paths_interim.append(p_rel_interim)

    # This manner of sorting is necessary to ensure that directories are removed after their contents
    all_current_paths_interim.sort(key=lambda p: (-len(p.parts), str(p)))
    return all_current_paths_interim


async def _deletable_choices(latest_revision_dir: pathlib.Path, target_dirs: set[pathlib.Path]) -> Any:
    # This should be -> list[tuple[str, str]], but that causes pyright to complain incorrectly
    # Details in pyright/dist/dist/typeshed-fallback/stubs/WTForms/wtforms/fields/choices.pyi
    # _Choice: TypeAlias = tuple[Any, str] | tuple[Any, str, dict[str, Any]]
    # Then it wants us to use list[_Choice] (= list[tuple[Any, str]])
    # But it says, incorrectly, that list[tuple[str, str]] is not a list[_Choice]
    # This mistake is not made by mypy
    empty_deletable_dirs: list[pathlib.Path] = []
    if latest_revision_dir.exists():
        for d_rel in target_dirs:
            if d_rel == pathlib.Path("."):
                # Disallow deletion of the root directory
                continue
            d_full = latest_revision_dir / d_rel
            if await aiofiles.os.path.isdir(d_full) and not await aiofiles.os.listdir(d_full):
                empty_deletable_dirs.append(d_rel)
    return sorted([(str(p), str(p)) for p in empty_deletable_dirs])


async def _delete_empty_directory(
    dir_to_delete_rel: pathlib.Path,
    session: routes.CommitterSession,
    project_name: str,
    version_name: str,
    respond: Respond,
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
        log.exception(f"Unexpected error deleting directory {dir_to_delete_rel} for {project_name}/{version_name}")
        return await respond(500, "An unexpected error occurred.")

    if creating.failed is not None:
        return await respond(400, str(creating.failed))
    return await respond(200, f"Deleted empty directory '{dir_to_delete_rel}'.")


async def _move_file_to_revision(
    source_files_rel: list[pathlib.Path],
    target_dir_rel: pathlib.Path,
    session: routes.CommitterSession,
    project_name: str,
    version_name: str,
    respond: Respond,
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
            return await respond(409, str(creating.failed))

        response_messages = []
        if moved_files_names:
            response_messages.append(f"Moved {', '.join(moved_files_names)}")
        if skipped_files_names:
            response_messages.append(f"Skipped {', '.join(skipped_files_names)} (already in target directory)")

        if not response_messages:
            if not source_files_rel:
                return await respond(400, "No source files specified for move.")
            msg = f"No files were moved. {', '.join(skipped_files_names)} already in '{target_dir_rel}'."
            return await respond(200, msg)

        return await respond(200, ". ".join(response_messages) + ".")

    except FileNotFoundError:
        log.exception("File not found during move operation in new revision")
        return await respond(400, "Error: Source file not found during move operation.")
    except OSError as e:
        log.exception("Error moving file in new revision")
        return await respond(500, f"Error moving file: {e}")
    except Exception as e:
        log.exception("Unexpected error during file move")
        return await respond(500, f"ERROR: {e!s}")


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


async def _remove_rc_tags(
    session: routes.CommitterSession,
    project_name: str,
    version_name: str,
    respond: Respond,
) -> tuple[quart_response.Response, int] | response.Response:
    description = "Remove RC tags from paths via web interface"
    error_messages: list[str] = []

    try:
        async with revision.create_and_manage(
            project_name, version_name, session.uid, description=description
        ) as creating:
            renamed_count = await _remove_rc_tags_revision(creating, error_messages)

        if creating.failed is not None:
            return await respond(409, str(creating.failed))

        if error_messages:
            status_ok = renamed_count > 0
            # TODO: Ideally HTTP would have a general mixed status, like 207 but for anything
            http_status = 200 if status_ok else 500
            msg = f"RC tags removed for {renamed_count} item(s) with some errors: {'; '.join(error_messages)}"
            return await respond(http_status, msg)

        if renamed_count > 0:
            return await respond(200, f"Successfully removed RC tags from {renamed_count} item(s).")

        return await respond(200, "No items required RC tag removal or no changes were made.")

    except Exception as e:
        return await respond(500, f"Unexpected error: {e!s}")


async def _remove_rc_tags_revision(
    creating: revision.Creating,
    error_messages: list[str],
) -> int:
    all_current_paths_interim = await _current_paths(creating)
    renamed_count_local = 0
    for path_rel_original_interim in all_current_paths_interim:
        path_rel_stripped_interim = analysis.candidate_removed(path_rel_original_interim)

        if path_rel_original_interim != path_rel_stripped_interim:
            # Absolute paths of the source and destination
            full_original_path = creating.interim_path / path_rel_original_interim
            full_stripped_path = creating.interim_path / path_rel_stripped_interim

            skip, renamed_count_local = await _remove_rc_tags_revision_item(
                path_rel_original_interim,
                full_original_path,
                full_stripped_path,
                error_messages,
                renamed_count_local,
            )
            if skip:
                continue

            try:
                if not await aiofiles.os.path.exists(full_stripped_path.parent):
                    # This could happen if e.g. a file is in an RC tagged directory
                    await aiofiles.os.makedirs(full_stripped_path.parent, exist_ok=True)

                if await aiofiles.os.path.exists(full_stripped_path):
                    error_messages.append(
                        f"Skipped '{path_rel_original_interim}': target '{path_rel_stripped_interim}' already exists."
                    )
                    continue

                await aiofiles.os.rename(full_original_path, full_stripped_path)
                renamed_count_local += 1
            except Exception as e:
                error_messages.append(f"Error renaming '{path_rel_original_interim}': {e}")
    return renamed_count_local


async def _remove_rc_tags_revision_item(
    path_rel_original_interim: pathlib.Path,
    full_original_path: pathlib.Path,
    full_stripped_path: pathlib.Path,
    error_messages: list[str],
    renamed_count_local: int,
) -> tuple[bool, int]:
    if await aiofiles.os.path.isdir(full_original_path):
        # If moving an RC tagged directory to an existing directory...
        is_target_dir_and_exists = await aiofiles.os.path.isdir(full_stripped_path)
        if is_target_dir_and_exists and (full_stripped_path != full_original_path):
            try:
                # And the source directory is empty...
                if not await aiofiles.os.listdir(full_original_path):
                    # This means we probably moved files out of the RC tagged directory
                    # In any case, we can't move it, so we have to delete it
                    await aiofiles.os.rmdir(full_original_path)
                    renamed_count_local += 1
                else:
                    error_messages.append(f"Source RC directory '{path_rel_original_interim}' is not empty, skipping.")
            except OSError as e:
                error_messages.append(f"Error removing source RC directory '{path_rel_original_interim}': {e}")
            return True, renamed_count_local
    return False, renamed_count_local


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


async def _submission_process(
    args: ProcessFormDataArgs,
) -> tuple[quart_response.Response, int] | response.Response | str | None:
    delete_empty_directory = "submit_delete_empty_dir" in args.formdata
    remove_rc_tags = "submit_remove_rc_tags" in args.formdata
    move_file = ("source_files" in args.formdata) and ("target_directory" in args.formdata)

    if delete_empty_directory:
        return await _submission_process_delete_empty_directory(args)

    if remove_rc_tags:
        return await _submission_process_remove_rc_tags(args)

    if move_file:
        return await _submission_process_move_file(args)

    return None


async def _submission_process_delete_empty_directory(
    args: ProcessFormDataArgs,
) -> tuple[quart_response.Response, int] | response.Response | str | None:
    if await args.delete_dir_form.validate_on_submit():
        dir_to_delete_str = args.delete_dir_form.directory_to_delete.data
        return await _delete_empty_directory(
            pathlib.Path(dir_to_delete_str), args.session, args.project_name, args.version_name, args.respond
        )
    elif args.wants_json:
        error_messages = []
        for field_name_str, error_list in args.delete_dir_form.errors.items():
            field_obj = getattr(args.delete_dir_form, field_name_str, None)
            label_text = field_name_str.replace("_", " ").title()
            if field_obj and hasattr(field_obj, "label") and field_obj.label:
                label_text = field_obj.label.text
            error_messages.append(f"{label_text}: {', '.join(error_list)}")
        error_msg = "; ".join(error_messages)
        return await args.respond(400, error_msg or "Invalid input.")
    return None


async def _submission_process_move_file(
    args: ProcessFormDataArgs,
) -> tuple[quart_response.Response, int] | response.Response | str | None:
    source_files_data = args.formdata.getlist("source_files")
    target_dir_data = args.formdata.get("target_directory")

    if not source_files_data or not target_dir_data:
        return await args.respond(400, "Missing source file(s) or target directory.")
    source_files_rel = [pathlib.Path(sf) for sf in source_files_data]
    target_dir_rel = pathlib.Path(target_dir_data)
    if not source_files_rel:
        return await args.respond(400, "No source files selected.")
    return await _move_file_to_revision(
        source_files_rel, target_dir_rel, args.session, args.project_name, args.version_name, args.respond
    )


async def _submission_process_remove_rc_tags(
    args: ProcessFormDataArgs,
) -> tuple[quart_response.Response, int] | response.Response | str | None:
    if await args.remove_rc_tags_form.validate_on_submit():
        return await _remove_rc_tags(args.session, args.project_name, args.version_name, args.respond)
    elif args.wants_json:
        return await args.respond(400, "Invalid request for RC tag removal.")
    return None
