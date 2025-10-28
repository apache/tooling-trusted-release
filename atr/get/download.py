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
from collections.abc import AsyncGenerator

import aiofiles
import aiofiles.os
import asfquart.base as base
import quart
import werkzeug.wrappers.response as response
import zipstream

import atr.blueprints.get as get
import atr.config as config
import atr.db as db
import atr.htm as htm
import atr.mapping as mapping
import atr.models.sql as sql
import atr.routes.root as root
import atr.template as template
import atr.util as util
import atr.web as web


@get.committer("/download/all/<project_name>/<version_name>")
async def all_selected(session: web.Committer, project_name: str, version_name: str) -> response.Response | str:
    """Display download commands for a release."""
    async with db.session() as data:
        release = await session.release(project_name=project_name, version_name=version_name, phase=None, data=data)
        if not release:
            return await session.redirect(root.index, error="Release not found")
        user_ssh_keys = await data.ssh_key(asf_uid=session.uid).all()

    back_url = mapping.release_as_url(release)

    return await template.render(
        "download-all.html",
        project_name=project_name,
        version_name=version_name,
        release=release,
        asf_id=session.uid,
        server_domain=session.app_host.split(":", 1)[0],
        server_host=session.app_host,
        user_ssh_keys=user_ssh_keys,
        back_url=back_url,
        get_release_stats=util.get_release_stats,
    )


@get.public("/download/path/<project_name>/<version_name>/<path:file_path>")
async def path(
    session: web.Committer | None, project_name: str, version_name: str, file_path: str
) -> response.Response | quart.Response:
    """Download a file or list a directory from a release in any phase."""
    return await _download_or_list(project_name, version_name, file_path)


@get.public("/download/path/<project_name>/<version_name>/")
async def path_empty(
    session: web.Committer | None, project_name: str, version_name: str
) -> response.Response | quart.Response:
    """List files at the root of a release directory for download."""
    return await _download_or_list(project_name, version_name, ".")


@get.public("/download/sh/<project_name>/<version_name>")
async def sh_selected(
    session: web.Committer | None, project_name: str, version_name: str
) -> response.Response | quart.Response:
    """Shell script to download a release."""
    conf = config.get()
    app_host = conf.APP_HOST
    script_path = (pathlib.Path(__file__).parent / "../static/sh/download-urls.sh").resolve()
    async with aiofiles.open(script_path) as f:
        content = await f.read()
    download_urls_selected = util.as_url(urls_selected, project_name=project_name, version_name=version_name)
    download_path = util.as_url(path, project_name=project_name, version_name=version_name, file_path="")
    content = content.replace("[URL_OF_URLS]", f"https://{app_host}{download_urls_selected}")
    content = content.replace("[URLS_PREFIX]", f"https://{app_host}{download_path}")
    return web.ShellResponse(content)


@get.public("/download/urls/<project_name>/<version_name>")
async def urls_selected(
    session: web.Committer | None, project_name: str, version_name: str
) -> response.Response | quart.Response:
    try:
        async with db.session() as data:
            release = await data.release(project_name=project_name, version=version_name).demand(
                ValueError("Release not found")
            )
        url_list_str = await _generate_file_url_list(release)
        return web.TextResponse(url_list_str)
    except ValueError as e:
        return web.TextResponse(f"Error: {e}", status=404)
    except Exception as e:
        return web.TextResponse(f"Internal server error: {e}", status=500)


@get.committer("/download/zip/<project_name>/<version_name>")
async def zip_selected(
    session: web.Committer, project_name: str, version_name: str
) -> response.Response | quart.wrappers.response.Response:
    try:
        release = await session.release(project_name=project_name, version_name=version_name, phase=None)
    except ValueError as e:
        return web.TextResponse(f"Error: {e}", status=404)
    except Exception as e:
        return web.TextResponse(f"Server error: {e}", status=500)

    base_dir = util.release_directory(release)
    files_to_zip = []
    try:
        async for rel_path in util.paths_recursive(base_dir):
            full_item_path = base_dir / rel_path
            if await aiofiles.os.path.isfile(full_item_path):
                files_to_zip.append({"file": str(full_item_path), "name": str(rel_path)})
    except FileNotFoundError:
        return web.TextResponse("Error: Release directory not found.", status=404)

    async def stream_zip(file_list: list[dict[str, str]]) -> AsyncGenerator[bytes]:
        aiozip = zipstream.AioZipStream(file_list, chunksize=32768)
        async for chunk in aiozip.stream():
            yield chunk

    headers = {
        "Content-Disposition": web.HeaderValue("attachment", filename=release.name + ".zip"),
        "Content-Type": web.HeaderValue("application/zip"),
    }
    return web.ZipResponse(stream_zip(files_to_zip), headers=headers)


async def _download_or_list(project_name: str, version_name: str, file_path: str) -> response.Response | quart.Response:
    """Download a file or list a directory from a release in any phase."""
    # await session.check_access(project_name)

    # Check that path is relative
    original_path = pathlib.Path(file_path)
    if (file_path != ".") and (not original_path.is_relative_to(original_path.anchor)):
        raise web.FlashError("Path must be relative")

    # We allow downloading files from any phase
    async with db.session() as data:
        release = await data.release(project_name=project_name, version=version_name).demand(
            base.ASFQuartException("Release does not exist", errorcode=404)
        )
    full_path = util.release_directory(release) / file_path

    if await aiofiles.os.path.isdir(full_path):
        return await _list(original_path, full_path, project_name, version_name, file_path)

    # Check that the path is a regular file
    if not await aiofiles.os.path.isfile(full_path):
        # Even using the following type declaration, mypy does not know the type
        # The same pattern is used in release.py, so this is a bug in mypy
        # TODO: Report the bug upstream to mypy
        await quart.flash("File or directory not found", "error")
        return quart.redirect(util.as_url(root.index))

    # Send the file with original filename
    return await quart.send_file(
        full_path, as_attachment=True, attachment_filename=original_path.name, mimetype="application/octet-stream"
    )


async def _generate_file_url_list(release: sql.Release) -> str:
    base_dir = util.release_directory(release)
    urls = []
    async for rel_path in util.paths_recursive(base_dir):
        full_item_path = base_dir / rel_path
        if await aiofiles.os.path.isfile(full_item_path):
            abs_url = util.as_url(
                path,
                project_name=release.project_name,
                version_name=release.version,
                file_path=str(rel_path),
                _external=True,
            )
            urls.append(abs_url + " " + str(rel_path))
    return "\n".join(sorted(urls)) + "\n"


async def _list(
    original_path: pathlib.Path, full_path: pathlib.Path, project_name: str, version_name: str, file_path: str
) -> response.Response | quart.Response:
    # Build a list of files in the directory
    files: list[pathlib.Path] = []
    for file in await aiofiles.os.listdir(full_path):
        file_in_dir = pathlib.Path(file)
        # Include subdirectories in listing
        is_file = await aiofiles.os.path.isfile(full_path / file_in_dir)
        is_dir = await aiofiles.os.path.isdir(full_path / file_in_dir)
        if is_file or is_dir:
            files.append(file_in_dir)
    files.sort()
    html = htm.Block(htm.html)
    html.style["body { margin: 1rem; font: 1.25rem/1.5 serif; }"]
    div = htm.Block()

    # Add link to parent directory if not at root
    if file_path != ".":
        parent_path_str = str(original_path.parent)
        parent_link_url = util.as_url(
            path,
            project_name=project_name,
            version_name=version_name,
            file_path=parent_path_str,
        )
        div.a(href=parent_link_url)["../"]

    # List files and directories
    for item_in_dir in files:
        relative_path_str = str(pathlib.Path(file_path) / item_in_dir)
        link_url = util.as_url(
            path,
            project_name=project_name,
            version_name=version_name,
            file_path=relative_path_str,
        )
        display_name = f"{item_in_dir}/" if await aiofiles.os.path.isdir(full_path / item_in_dir) else str(item_in_dir)
        div.a(href=link_url)[display_name]
    html.body[div.collect(separator=htm.br)]
    response_body = html.collect()
    return web.ElementResponse(response_body)
