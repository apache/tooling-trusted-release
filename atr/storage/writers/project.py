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

# Removing this will cause circular imports
from __future__ import annotations

import datetime

import atr.db as db
import atr.models.sql as sql
import atr.registry as registry
import atr.storage as storage
import atr.util as util


class GeneralPublic:
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsGeneralPublic,
        data: db.Session,
    ):
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        self.__asf_uid = write.authorisation.asf_uid


class FoundationCommitter(GeneralPublic):
    def __init__(self, write: storage.Write, write_as: storage.WriteAsFoundationCommitter, data: db.Session):
        super().__init__(write, write_as, data)
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid


class CommitteeParticipant(FoundationCommitter):
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsCommitteeParticipant,
        data: db.Session,
        committee_name: str,
    ):
        super().__init__(write, write_as, data)
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name


class CommitteeMember(CommitteeParticipant):
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsCommitteeMember,
        data: db.Session,
        committee_name: str,
    ):
        super().__init__(write, write_as, data, committee_name)
        self.__write = write
        self.__write_as = write_as
        self.__data = data
        asf_uid = write.authorisation.asf_uid
        if asf_uid is None:
            raise storage.AccessError("No ASF UID")
        self.__asf_uid = asf_uid
        self.__committee_name = committee_name

    async def category_add(self, project: sql.Project, new_category: str) -> bool:
        project = await self.__data.merge(project)
        new_category = new_category.strip()
        current_categories = self.__current_categories(project)
        if new_category and (new_category not in current_categories):
            if ":" in new_category:
                raise ValueError(f"Category '{new_category}' contains a colon")
            if new_category in registry.FORBIDDEN_PROJECT_CATEGORIES:
                raise ValueError(f"Category '{new_category}' may not be added or removed")
            current_categories.append(new_category)
            current_categories.sort()
            project.category = ", ".join(current_categories)
            if project.category == "":
                project.category = None
            await self.__data.commit()
            return True
        return False

    async def category_remove(self, project: sql.Project, action_value: str) -> bool:
        project = await self.__data.merge(project)
        current_categories = self.__current_categories(project)
        if action_value in current_categories:
            if action_value in registry.FORBIDDEN_PROJECT_CATEGORIES:
                raise ValueError(f"Category '{action_value}' may not be added or removed")
            current_categories.remove(action_value)
            project.category = ", ".join(current_categories)
            if project.category == "":
                project.category = None
            await self.__data.commit()
            return True
        return False

    async def create(self, committee_name: str, display_name: str, label: str) -> None:
        super_project = None
        # Get the base project to derive from
        # We're allowing derivation from a retired project here
        # TODO: Should we disallow this instead?
        committee_projects = await self.__data.project(committee_name=committee_name, _committee=True).all()
        for committee_project in committee_projects:
            if label.startswith(committee_project.name + "-"):
                if (super_project is None) or (len(super_project.name) < len(committee_project.name)):
                    super_project = committee_project

        # Check whether the project already exists
        if await self.__data.project(name=label).get():
            raise storage.AccessError(f"Project {label} already exists")

        # TODO: Fix the potential race condition here
        project = sql.Project(
            name=label,
            full_name=display_name,
            status=sql.ProjectStatus.ACTIVE,
            super_project_name=super_project.name if super_project else None,
            description=super_project.description if super_project else None,
            category=super_project.category if super_project else None,
            programming_languages=super_project.programming_languages if super_project else None,
            committee_name=committee_name,
            release_policy_id=super_project.release_policy_id if super_project else None,
            created=datetime.datetime.now(datetime.UTC),
            created_by=self.__asf_uid,
        )

        self.__data.add(project)
        await self.__data.commit()

    async def delete(self, project_name: str) -> None:
        project = await self.__data.project(
            name=project_name, status=sql.ProjectStatus.ACTIVE, _releases=True, _distribution_channels=True
        ).get()

        if not project:
            raise storage.AccessError(f"Project '{project_name}' not found.")

        # Check for ownership or admin status
        # TODO: Should use FoundationCommitter for the latter check
        is_owner = project.created_by == self.__asf_uid
        is_privileged = util.is_user_viewing_as_admin(self.__asf_uid)

        if not (is_owner or is_privileged):
            raise storage.AccessError(f"You do not have permission to delete project '{project_name}'.")

        # Prevent deletion if there are associated releases or channels
        if project.releases:
            raise storage.AccessError(f"Cannot delete project '{project_name}' because it has associated releases.")

        await self.__data.delete(project)
        await self.__data.commit()
        self.__write_as.append_to_audit_log(
            action="project.delete",
            project_name=project_name,
        )
        return None

    async def language_add(self, project: sql.Project, new_language: str) -> bool:
        project = await self.__data.merge(project)
        new_language = new_language.strip()
        current_languages = self.__current_languages(project)
        if new_language and (new_language not in current_languages):
            if ":" in new_language:
                raise ValueError(f"Language '{new_language}' contains a colon")
            current_languages.append(new_language)
            current_languages.sort()
            project.programming_languages = ", ".join(current_languages)
            if project.programming_languages == "":
                project.programming_languages = None
            await self.__data.commit()
            return True
        return False

    async def language_remove(self, project: sql.Project, action_value: str) -> bool:
        project = await self.__data.merge(project)
        current_languages = self.__current_languages(project)
        if action_value in current_languages:
            current_languages.remove(action_value)
            project.programming_languages = ", ".join(current_languages)
            if project.programming_languages == "":
                project.programming_languages = None
            await self.__data.commit()
            return True
        return False

    def __current_categories(self, project: sql.Project) -> list[str]:
        return (
            [category.strip() for category in (project.category or "").split(",") if category.strip()]
            if project.category
            else []
        )

    def __current_languages(self, project: sql.Project) -> list[str]:
        return (
            [language.strip() for language in (project.programming_languages or "").split(",") if language.strip()]
            if project.programming_languages
            else []
        )
