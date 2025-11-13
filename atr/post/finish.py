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

import pathlib

import quart

import atr.blueprints.post as post
import atr.log as log
import atr.shared as shared
import atr.storage as storage
import atr.web as web


@post.committer("/finish/<project_name>/<version_name>")
@post.form(shared.finish.FinishForm)
async def selected(
    session: web.Committer, finish_form: shared.finish.FinishForm, project_name: str, version_name: str
) -> tuple[web.QuartResponse, int] | web.WerkzeugResponse:
    wants_json = quart.request.accept_mimetypes.best_match(["application/json", "text/html"]) == "application/json"
    respond = _respond_helper(session, project_name, version_name, wants_json)

    match finish_form:
        case shared.finish.DeleteEmptyDirectoryForm() as delete_form:
            return await _delete_empty_directory(delete_form, session, project_name, version_name, respond)
        case shared.finish.MoveFileForm() as move_form:
            return await _move_file_to_revision(move_form, session, project_name, version_name, respond)
        case shared.finish.RemoveRCTagsForm():
            return await _remove_rc_tags(session, project_name, version_name, respond)


async def _delete_empty_directory(
    delete_form: shared.finish.DeleteEmptyDirectoryForm,
    session: web.Committer,
    project_name: str,
    version_name: str,
    respond: shared.finish.Respond,
) -> tuple[web.QuartResponse, int] | web.WerkzeugResponse:
    dir_to_delete_rel = pathlib.Path(delete_form.directory_to_delete)
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
    move_form: shared.finish.MoveFileForm,
    session: web.Committer,
    project_name: str,
    version_name: str,
    respond: shared.finish.Respond,
) -> tuple[web.QuartResponse, int] | web.WerkzeugResponse:
    source_files_rel = [pathlib.Path(sf) for sf in move_form.source_files]
    target_dir_rel = pathlib.Path(move_form.target_directory)
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
    respond: shared.finish.Respond,
) -> tuple[web.QuartResponse, int] | web.WerkzeugResponse:
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


def _respond_helper(
    session: web.Committer, project_name: str, version_name: str, wants_json: bool
) -> shared.finish.Respond:
    """Create a response helper function for the finish route."""
    import atr.get as get

    async def respond(
        http_status: int,
        msg: str,
    ) -> tuple[web.QuartResponse, int] | web.WerkzeugResponse:
        ok = http_status < 300
        if wants_json:
            return quart.jsonify(ok=ok, message=msg), http_status
        await quart.flash(msg, "success" if ok else "error")
        return await session.redirect(get.finish.selected, project_name=project_name, version_name=version_name)

    return respond
