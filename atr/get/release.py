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

import asfquart.base as base
import werkzeug.wrappers.response as response

import atr.blueprints.get as get
import atr.db as db
import atr.db.interaction as interaction
import atr.models.sql as sql
import atr.template as template
import atr.util as util
import atr.web as web


@get.public("/releases/finished/<project_name>")
async def finished(session: web.Committer | None, project_name: str) -> str:
    """View all finished releases for a project."""
    async with db.session() as data:
        project = await data.project(name=project_name, status=sql.ProjectStatus.ACTIVE).demand(
            base.ASFQuartException(f"Project {project_name} not found", errorcode=404)
        )

        releases = await data.release(
            project_name=project.name,
            phase=sql.ReleasePhase.RELEASE,
            _committee=True,
        ).all()

    def sort_releases(release: sql.Release) -> datetime.datetime:
        return release.released or release.created

    releases = sorted(releases, key=sort_releases, reverse=True)

    return await template.render(
        "releases-finished.html", project=project, releases=releases, format_datetime=util.format_datetime
    )


@get.public("/releases")
async def releases(session: web.Committer | None) -> str:
    """View all releases."""
    # Releases are public, so we don't need to filter by user
    async with db.session() as data:
        releases = await data.release(
            phase=sql.ReleasePhase.RELEASE,
            _committee=True,
            _project=True,
        ).all()

    projects = {}
    for release in releases:
        if release.project.display_name not in projects:
            projects[release.project.display_name] = (release.project, 1)
        else:
            projects[release.project.display_name] = (release.project, projects[release.project.display_name][1] + 1)

    return await template.render(
        "releases.html",
        projects=projects,
        releases=releases,
    )


@get.committer("/release/select/<project_name>")
async def select(session: web.Committer, project_name: str) -> str:
    """Show releases in progress for a project."""
    await session.check_access(project_name)

    async with db.session() as data:
        project = await data.project(name=project_name, status=sql.ProjectStatus.ACTIVE, _releases=True).demand(
            base.ASFQuartException(f"Project {project_name} not found", errorcode=404)
        )
        releases = await interaction.releases_in_progress(project)
    return await template.render(
        "release-select.html", project=project, releases=releases, format_datetime=util.format_datetime
    )


@get.public("/release/view/<project_name>/<version_name>")
async def view(session: web.Committer | None, project_name: str, version_name: str) -> response.Response | str:
    """View all the files in the rsync upload directory for a release."""
    async with db.session() as data:
        release_name = sql.release_name(project_name, version_name)
        release = await data.release(name=release_name, _project=True).demand(
            base.ASFQuartException(f"Release {version_name} not found", errorcode=404)
        )

    # Convert async generator to list
    file_stats = [stat async for stat in util.content_list(util.get_finished_dir(), project_name, version_name)]
    # Sort the files by FileStat.path
    file_stats.sort(key=lambda fs: fs.path)

    return await template.render(
        # TODO: Move to somewhere appropriate
        "phase-view.html",
        file_stats=file_stats,
        release=release,
        format_datetime=util.format_datetime,
        format_file_size=util.format_file_size,
        format_permissions=util.format_permissions,
        phase="release",
        phase_key="release",
    )


@get.public("/release/view/<project_name>/<version_name>/<path:file_path>")
async def view_path(
    session: web.Committer | None, project_name: str, version_name: str, file_path: str
) -> response.Response | str:
    """View the content of a specific file in the final release."""
    async with db.session() as data:
        release_name = sql.release_name(project_name, version_name)
        release = await data.release(name=release_name, _project=True).demand(
            base.ASFQuartException(f"Release {version_name} not found", errorcode=404)
        )
    _max_view_size = 1 * 1024 * 1024
    full_path = util.release_directory(release) / file_path
    content_listing = await util.archive_listing(full_path)
    content, is_text, is_truncated, error_message = await util.read_file_for_viewer(full_path, _max_view_size)
    return await template.render(
        "file-selected-path.html",
        release=release,
        project_name=project_name,
        version_name=version_name,
        file_path=file_path,
        content=content,
        is_text=is_text,
        is_truncated=is_truncated,
        error_message=error_message,
        format_file_size=util.format_file_size,
        phase_key="release",
        content_listing=content_listing,
    )
