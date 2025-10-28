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
from typing import Any

import aiofiles.os
import asfquart.base as base
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
import atr.mapping as mapping
import atr.models.sql as sql
import atr.storage as storage
import atr.template as template
import atr.util as util
import atr.web as web

type Respond = Callable[[int, str], Awaitable[tuple[quart_response.Response, int] | response.Response]]


class DeleteEmptyDirectoryForm(forms.Typed):
    """Form for deleting an empty directory within a preview revision."""

    directory_to_delete = forms.select("Directory to delete")
    submit_delete_empty_dir = forms.submit("Delete directory")


class MoveFileForm(forms.Typed):
    """Form for moving one or more files within a preview revision."""

    source_files = forms.multiple("Files to move")
    target_directory = forms.select("Target directory", validate_choice=False)
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
    submit_remove_rc_tags = forms.submit("Remove RC tags")


@dataclasses.dataclass
class ProcessFormDataArgs:
    formdata: datastructures.MultiDict
    session: web.Committer
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


async def selected(
    session: web.Committer, project_name: str, version_name: str
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
        release = await data.release(
            project_name=project_name,
            version=version_name,
            _committee=True,
        ).demand(base.ASFQuartException("Release does not exist", errorcode=404))
    if release.phase != sql.ReleasePhase.RELEASE_PREVIEW:
        return await mapping.release_as_redirect(session, release)
    user_ssh_keys = await data.ssh_key(asf_uid=session.uid).all()

    latest_revision_dir = util.release_directory(release)
    try:
        source_files_rel, target_dirs = await _sources_and_targets(latest_revision_dir)
    except FileNotFoundError:
        import atr.get as get

        await quart.flash("Preview revision directory not found.", "error")
        return await session.redirect(get.root.index)

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
        r.affected_paths_preview.append((original_path_str, stripped_path_str))

    return r


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
    session: web.Committer,
    project_name: str,
    version_name: str,
    respond: Respond,
) -> tuple[quart_response.Response, int] | response.Response:
    try:
        async with storage.write(session) as write:
            wacp = await write.as_project_committee_member(project_name)
            creation_error = await wacp.release.delete_empty_directory(project_name, version_name, dir_to_delete_rel)
    except Exception:
        log.exception(f"Unexpected error deleting directory {dir_to_delete_rel} for {project_name}/{version_name}")
        return await respond(500, "An unexpected error occurred.")

    if creation_error is not None:
        return await respond(400, creation_error)
    return await respond(200, f"Deleted empty directory '{dir_to_delete_rel}'.")


async def _move_file_to_revision(
    source_files_rel: list[pathlib.Path],
    target_dir_rel: pathlib.Path,
    session: web.Committer,
    project_name: str,
    version_name: str,
    respond: Respond,
) -> tuple[quart_response.Response, int] | response.Response:
    try:
        async with storage.write(session) as write:
            wacp = await write.as_project_committee_member(project_name)
            creation_error, moved_files_names, skipped_files_names = await wacp.release.move_file(
                project_name, version_name, source_files_rel, target_dir_rel
            )

        if creation_error is not None:
            return await respond(409, creation_error)

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


async def _remove_rc_tags(
    session: web.Committer,
    project_name: str,
    version_name: str,
    respond: Respond,
) -> tuple[quart_response.Response, int] | response.Response:
    try:
        async with storage.write(session) as write:
            wacp = await write.as_project_committee_member(project_name)
            creation_error, renamed_count, error_messages = await wacp.release.remove_rc_tags(
                project_name, version_name
            )

        if creation_error is not None:
            return await respond(409, creation_error)

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
