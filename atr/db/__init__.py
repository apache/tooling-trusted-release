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

from __future__ import annotations

import contextlib
import functools
import os
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Concatenate, Final, TypeGuard, TypeVar

import alembic.command as command
import alembic.config as alembic_config
import sqlalchemy
import sqlalchemy.dialects.sqlite
import sqlalchemy.ext.asyncio
import sqlalchemy.orm as orm
import sqlalchemy.sql
import sqlmodel
import sqlmodel.sql.expression as expression

import atr.config as config
import atr.log as log
import atr.models.schema as schema
import atr.models.sql as sql
import atr.util as util

if TYPE_CHECKING:
    import datetime
    from collections.abc import Awaitable, Callable, Iterator, Sequence

    import asfquart.base as base

global_log_query: bool = False
_global_atr_engine: sqlalchemy.ext.asyncio.AsyncEngine | None = None
_global_atr_sessionmaker: sqlalchemy.ext.asyncio.async_sessionmaker | None = None


T = TypeVar("T")
R = TypeVar("R")


class NotSet:
    """
    A marker class to indicate that a value is not set and thus should
    not be considered. This is different to None.
    """

    _instance = None

    def __new__(cls):  # type: ignore
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "<NotSet>"

    def __copy__(self):  # type: ignore
        return NotSet

    def __deepcopy__(self, memo: dict[int, Any]):  # type: ignore
        return NotSet


NOT_SET: Final[NotSet] = NotSet()
type Opt[T] = T | NotSet


class Query[T]:
    def __init__(self, session: Session, query: expression.SelectOfScalar[T]):
        self.query = query
        self.session = session

    def order_by(self, *args: Any, **kwargs: Any) -> Query[T]:
        self.query = self.query.order_by(*args, **kwargs)
        return self

    def log_query(self, method_name: str, log_query: bool) -> None:
        if not (self.session.log_queries or global_log_query or log_query):
            return
        try:
            compiled_query = self.query.compile(self.session.bind, compile_kwargs={"literal_binds": True})
            log.info(f"Executing query ({method_name}): {compiled_query}")
        except Exception as e:
            log.error(f"Error compiling query for logging ({method_name}): {e}")

    async def get(self, log_query: bool = False) -> T | None:
        self.log_query("get", log_query)
        result = await self.session.execute(self.query)
        return result.unique().scalar_one_or_none()

    async def demand(self, error: Exception, log_query: bool = False) -> T:
        self.log_query("demand", log_query)
        result = await self.session.execute(self.query)
        item = result.unique().scalar_one_or_none()
        if item is None:
            raise error
        return item

    async def all(self, log_query: bool = False) -> Sequence[T]:
        self.log_query("all", log_query)
        result = await self.session.execute(self.query)
        return result.scalars().all()

    async def bulk_upsert(self, items: list[schema.Strict], log_query: bool = False) -> None:
        if not items:
            return

        self.log_query("bulk_upsert", log_query)
        model_class = self.query.column_descriptions[0]["type"]
        stmt = sqlalchemy.dialects.sqlite.insert(model_class).values([item.model_dump() for item in items])
        # TODO: The primary key might not be the index element
        # For example, we might have a unique constraint on other columns
        primary_keys = [key.name for key in sqlalchemy.inspect(model_class).primary_key]
        update_cols = {
            col.name: getattr(stmt.excluded, col.name)
            for col in sqlalchemy.inspect(model_class).c
            if col.name not in primary_keys
        }
        stmt = stmt.on_conflict_do_update(index_elements=primary_keys, set_=update_cols)
        await self.session.execute(stmt)

    # async def execute(self) -> sqlalchemy.Result[tuple[T]]:
    #     return await self.session.execute(self.query)


class Session(sqlalchemy.ext.asyncio.AsyncSession):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        explicit_value_passed_by_sessionmaker = kwargs.pop("log_queries", None)
        super().__init__(*args, **kwargs)

        self.log_queries: bool = global_log_query
        if explicit_value_passed_by_sessionmaker is not None:
            self.log_queries = explicit_value_passed_by_sessionmaker

    # TODO: Need to type all of these arguments correctly

    async def begin_immediate(self) -> None:
        await self.execute(sqlalchemy.text("BEGIN IMMEDIATE"))

    def check_result(
        self,
        id: Opt[int] = NOT_SET,
        release_name: Opt[str] = NOT_SET,
        revision_number: Opt[str] = NOT_SET,
        checker: Opt[str] = NOT_SET,
        primary_rel_path: Opt[str | None] = NOT_SET,
        member_rel_path: Opt[str | None] = NOT_SET,
        created: Opt[datetime.datetime] = NOT_SET,
        status: Opt[sql.CheckResultStatus] = NOT_SET,
        message: Opt[str] = NOT_SET,
        data: Opt[Any] = NOT_SET,
        _release: bool = False,
    ) -> Query[sql.CheckResult]:
        query = sqlmodel.select(sql.CheckResult)

        if is_defined(id):
            query = query.where(sql.CheckResult.id == id)
        if is_defined(release_name):
            query = query.where(sql.CheckResult.release_name == release_name)
        if is_defined(revision_number):
            query = query.where(sql.CheckResult.revision_number == revision_number)
        if is_defined(checker):
            query = query.where(sql.CheckResult.checker == checker)
        if is_defined(primary_rel_path):
            query = query.where(sql.CheckResult.primary_rel_path == primary_rel_path)
        if is_defined(member_rel_path):
            query = query.where(sql.CheckResult.member_rel_path == member_rel_path)
        if is_defined(created):
            query = query.where(sql.CheckResult.created == created)
        if is_defined(status):
            query = query.where(sql.CheckResult.status == status)
        if is_defined(message):
            query = query.where(sql.CheckResult.message == message)
        if is_defined(data):
            query = query.where(sql.CheckResult.data == data)

        if _release:
            query = query.options(joined_load(sql.CheckResult.release))

        return Query(self, query)

    def check_result_ignore(
        self,
        committee_name: Opt[str] = NOT_SET,
        release_glob: Opt[str] = NOT_SET,
        revision_number: Opt[str] = NOT_SET,
        checker_glob: Opt[str] = NOT_SET,
        primary_rel_path_glob: Opt[str] = NOT_SET,
        member_rel_path_glob: Opt[str] = NOT_SET,
        status: Opt[sql.CheckResultStatusIgnore] = NOT_SET,
        message_glob: Opt[str] = NOT_SET,
    ) -> Query[sql.CheckResultIgnore]:
        query = sqlmodel.select(sql.CheckResultIgnore)

        if is_defined(committee_name):
            query = query.where(sql.CheckResultIgnore.committee_name == committee_name)
        if is_defined(release_glob):
            query = query.where(sql.CheckResultIgnore.release_glob == release_glob)
        if is_defined(revision_number):
            query = query.where(sql.CheckResultIgnore.revision_number == revision_number)
        if is_defined(checker_glob):
            query = query.where(sql.CheckResultIgnore.checker_glob == checker_glob)
        if is_defined(primary_rel_path_glob):
            query = query.where(sql.CheckResultIgnore.primary_rel_path_glob == primary_rel_path_glob)
        if is_defined(member_rel_path_glob):
            query = query.where(sql.CheckResultIgnore.member_rel_path_glob == member_rel_path_glob)
        if is_defined(status):
            query = query.where(sql.CheckResultIgnore.status == status)
        if is_defined(message_glob):
            query = query.where(sql.CheckResultIgnore.message_glob == message_glob)

        return Query(self, query)

    def committee(
        self,
        name: Opt[str] = NOT_SET,
        full_name: Opt[str] = NOT_SET,
        is_podling: Opt[bool] = NOT_SET,
        parent_committee_name: Opt[str] = NOT_SET,
        committee_members: Opt[list[str]] = NOT_SET,
        committers: Opt[list[str]] = NOT_SET,
        release_managers: Opt[list[str]] = NOT_SET,
        name_in: Opt[list[str]] = NOT_SET,
        has_member: Opt[str] = NOT_SET,
        has_committer: Opt[str] = NOT_SET,
        has_participant: Opt[str] = NOT_SET,
        _child_committees: bool = False,
        _projects: bool = False,
        _public_signing_keys: bool = False,
    ) -> Query[sql.Committee]:
        via = sql.validate_instrumented_attribute
        query = sqlmodel.select(sql.Committee)

        if is_defined(name):
            query = query.where(sql.Committee.name == name)
        if is_defined(full_name):
            query = query.where(sql.Committee.full_name == full_name)
        if is_defined(is_podling):
            query = query.where(sql.Committee.is_podling == is_podling)
        if is_defined(parent_committee_name):
            query = query.where(sql.Committee.parent_committee_name == parent_committee_name)
        if is_defined(committee_members):
            query = query.where(sql.Committee.committee_members == committee_members)
        if is_defined(committers):
            query = query.where(sql.Committee.committers == committers)
        if is_defined(release_managers):
            query = query.where(sql.Committee.release_managers == release_managers)

        if is_defined(name_in):
            query = query.where(via(sql.Committee.name).in_(name_in))
        if is_defined(has_member):
            query = query.where(via(sql.Committee.committee_members).contains(has_member))
        if is_defined(has_committer):
            query = query.where(via(sql.Committee.committers).contains(has_committer))
        if is_defined(has_participant):
            query = query.where(
                via(sql.Committee.committee_members).contains(has_participant)
                | via(sql.Committee.committers).contains(has_participant)
            )

        if _child_committees:
            query = query.options(select_in_load(sql.Committee.child_committees))
        if _projects:
            query = query.options(select_in_load(sql.Committee.projects))
        if _public_signing_keys:
            query = query.options(select_in_load(sql.Committee.public_signing_keys))

        return Query(self, query)

    async def execute_query(self, query: sqlalchemy.sql.expression.Executable) -> sqlalchemy.engine.Result:
        if (self.log_queries or global_log_query) and isinstance(query, sqlalchemy.sql.expression.Select):
            try:
                dialect = self.bind.dialect if self.bind else sqlalchemy.dialects.sqlite.dialect()
                compiled_query = query.compile(dialect=dialect, compile_kwargs={"literal_binds": True})
                log.info(f"Executing query (execute_query): {compiled_query}")
            except Exception as e:
                log.error(f"Error compiling query for logging: {e}")
        execution_result: sqlalchemy.engine.Result = await self.execute(query)
        return execution_result

    async def ns_text_del(self, ns: str, key: str, commit: bool = True) -> None:
        stmt = sqlalchemy.delete(sql.TextValue).where(
            sql.validate_instrumented_attribute(sql.TextValue.ns) == ns,
            sql.validate_instrumented_attribute(sql.TextValue.key) == key,
        )
        await self.execute(stmt)
        if commit is True:
            await self.commit()

    async def ns_text_del_all(self, ns: str, commit: bool = True) -> None:
        stmt = sqlalchemy.delete(sql.TextValue).where(
            sql.validate_instrumented_attribute(sql.TextValue.ns) == ns,
        )
        await self.execute(stmt)
        if commit is True:
            await self.commit()

    async def ns_text_get(self, ns: str, key: str) -> str | None:
        stmt = sqlalchemy.select(sql.TextValue).where(
            sql.validate_instrumented_attribute(sql.TextValue.ns) == ns,
            sql.validate_instrumented_attribute(sql.TextValue.key) == key,
        )
        result = await self.execute(stmt)
        match result.scalar_one_or_none():
            case sql.TextValue(value=value):
                return value
            case None:
                return None

    async def ns_text_set(self, ns: str, key: str, value: str, commit: bool = True) -> None:
        # Don't use sql.insert(), it won't give on_conflict_do_update()
        stmt = sqlalchemy.dialects.sqlite.insert(sql.TextValue).values((ns, key, value))
        stmt = stmt.on_conflict_do_update(index_elements=[sql.TextValue.ns, sql.TextValue.key], set_=dict(value=value))
        await self.execute(stmt)
        if commit is True:
            await self.commit()

    def project(
        self,
        name: Opt[str] = NOT_SET,
        full_name: Opt[str] = NOT_SET,
        committee_name: Opt[str] = NOT_SET,
        release_policy_id: Opt[int] = NOT_SET,
        status: Opt[sql.ProjectStatus] = NOT_SET,
        _committee: bool = True,
        _releases: bool = False,
        _distribution_channels: bool = False,
        _super_project: bool = False,
        _release_policy: bool = False,
        _committee_public_signing_keys: bool = False,
    ) -> Query[sql.Project]:
        query = sqlmodel.select(sql.Project)

        if is_defined(name):
            query = query.where(sql.Project.name == name)
        if is_defined(full_name):
            query = query.where(sql.Project.full_name == full_name)
        if is_defined(committee_name):
            query = query.where(sql.Project.committee_name == committee_name)
        if is_defined(release_policy_id):
            query = query.where(sql.Project.release_policy_id == release_policy_id)
        if is_defined(status):
            query = query.where(sql.Project.status == status)

        # Avoid multiple loaders for Project.committee on the same path
        if _committee_public_signing_keys:
            query = query.options(
                joined_load(sql.Project.committee).selectinload(
                    sql.validate_instrumented_attribute(sql.Committee.public_signing_keys)
                )
            )
        elif _committee:
            query = query.options(joined_load(sql.Project.committee))

        if _releases:
            query = query.options(select_in_load(sql.Project.releases))
        if _distribution_channels:
            query = query.options(select_in_load(sql.Project.distribution_channels))
        if _super_project:
            query = query.options(joined_load(sql.Project.super_project))
        if _release_policy:
            query = query.options(joined_load(sql.Project.release_policy))

        return Query(self, query)

    def public_signing_key(
        self,
        fingerprint: Opt[str] = NOT_SET,
        algorithm: Opt[str] = NOT_SET,
        length: Opt[int] = NOT_SET,
        created: Opt[datetime.datetime] = NOT_SET,
        expires: Opt[datetime.datetime | None] = NOT_SET,
        primary_declared_uid: Opt[str | None] = NOT_SET,
        secondary_declared_uids: Opt[list[str]] = NOT_SET,
        apache_uid: Opt[str | None] = NOT_SET,
        ascii_armored_key: Opt[str] = NOT_SET,
        _committees: bool = False,
    ) -> Query[sql.PublicSigningKey]:
        query = sqlmodel.select(sql.PublicSigningKey)

        if is_defined(fingerprint):
            query = query.where(sql.PublicSigningKey.fingerprint == fingerprint)
        if is_defined(algorithm):
            query = query.where(sql.PublicSigningKey.algorithm == algorithm)
        if is_defined(length):
            query = query.where(sql.PublicSigningKey.length == length)
        if is_defined(created):
            query = query.where(sql.PublicSigningKey.created == created)
        if is_defined(expires):
            query = query.where(sql.PublicSigningKey.expires == expires)
        if is_defined(primary_declared_uid):
            query = query.where(sql.PublicSigningKey.primary_declared_uid == primary_declared_uid)
        if is_defined(secondary_declared_uids):
            query = query.where(sql.PublicSigningKey.secondary_declared_uids == secondary_declared_uids)
        if is_defined(apache_uid):
            query = query.where(sql.PublicSigningKey.apache_uid == apache_uid)
        if is_defined(ascii_armored_key):
            query = query.where(sql.PublicSigningKey.ascii_armored_key == ascii_armored_key)

        if _committees:
            query = query.options(select_in_load(sql.PublicSigningKey.committees))

        return Query(self, query)

    async def query_all(self, stmt: sqlalchemy.Select[Any]) -> list[Any]:
        result = await self.execute(stmt)
        return list(result.scalars().all())

    async def query_first(self, stmt: sqlalchemy.Select[Any]) -> Any | None:
        result = await self.execute(stmt)
        return result.scalars().first()

    async def query_one(self, stmt: sqlalchemy.Select[Any]) -> Any:
        result = await self.execute(stmt)
        return result.scalars().one()

    async def query_one_or_none(self, stmt: sqlalchemy.Select[Any]) -> Any | None:
        result = await self.execute(stmt)
        return result.scalars().one_or_none()

    def release(
        self,
        name: Opt[str] = NOT_SET,
        phase: Opt[sql.ReleasePhase] = NOT_SET,
        created: Opt[datetime.datetime] = NOT_SET,
        project_name: Opt[str] = NOT_SET,
        package_managers: Opt[list[str]] = NOT_SET,
        version: Opt[str] = NOT_SET,
        sboms: Opt[list[str]] = NOT_SET,
        release_policy_id: Opt[int] = NOT_SET,
        votes: Opt[list[sql.VoteEntry]] = NOT_SET,
        latest_revision_number: Opt[str | None] = NOT_SET,
        _project: bool = True,
        _committee: bool = True,
        _release_policy: bool = False,
        _project_release_policy: bool = False,
        _revisions: bool = False,
    ) -> Query[sql.Release]:
        query = sqlmodel.select(sql.Release)

        if is_defined(name):
            query = query.where(sql.Release.name == name)
        if is_defined(phase):
            query = query.where(sql.Release.phase == phase)
        if is_defined(created):
            query = query.where(sql.Release.created == created)
        if is_defined(project_name):
            query = query.where(sql.Release.project_name == project_name)
        if is_defined(package_managers):
            query = query.where(sql.Release.package_managers == package_managers)
        if is_defined(version):
            query = query.where(sql.Release.version == version)
        if is_defined(sboms):
            query = query.where(sql.Release.sboms == sboms)
        if is_defined(release_policy_id):
            query = query.where(sql.Release.release_policy_id == release_policy_id)
        if is_defined(votes):
            query = query.where(sql.Release.votes == votes)
        if is_defined(latest_revision_number):
            # Must define the subquery explicitly, mirroring the column_property
            # In other words, this doesn't work:
            # query = query.where(models.Release.latest_revision_number == latest_revision_number)
            query = query.where(sql.latest_revision_number_query() == latest_revision_number)

        # Avoid multiple loaders for Release.project on the same path
        if _committee:
            query = query.options(joined_load_nested(sql.Release.project, sql.Project.committee))
        elif _project:
            query = query.options(joined_load(sql.Release.project))

        if _release_policy:
            query = query.options(joined_load(sql.Release.release_policy))
        if _project_release_policy:
            query = query.options(joined_load_nested(sql.Release.project, sql.Project.release_policy))
        if _revisions:
            query = query.options(select_in_load(sql.Release.revisions))

        return Query(self, query)

    def release_policy(
        self,
        id: Opt[int] = NOT_SET,
        mailto_addresses: Opt[list[str]] = NOT_SET,
        manual_vote: Opt[bool] = NOT_SET,
        min_hours: Opt[int] = NOT_SET,
        release_checklist: Opt[str] = NOT_SET,
        pause_for_rm: Opt[bool] = NOT_SET,
        _project: bool = False,
    ) -> Query[sql.ReleasePolicy]:
        query = sqlmodel.select(sql.ReleasePolicy)

        if is_defined(id):
            query = query.where(sql.ReleasePolicy.id == id)
        if is_defined(mailto_addresses):
            query = query.where(sql.ReleasePolicy.mailto_addresses == mailto_addresses)
        if is_defined(manual_vote):
            query = query.where(sql.ReleasePolicy.manual_vote == manual_vote)
        if is_defined(min_hours):
            query = query.where(sql.ReleasePolicy.min_hours == min_hours)
        if is_defined(release_checklist):
            query = query.where(sql.ReleasePolicy.release_checklist == release_checklist)
        if is_defined(pause_for_rm):
            query = query.where(sql.ReleasePolicy.pause_for_rm == pause_for_rm)

        if _project:
            query = query.options(joined_load(sql.ReleasePolicy.project))

        return Query(self, query)

    def revision(
        self,
        name: Opt[str] = NOT_SET,
        release_name: Opt[str] = NOT_SET,
        seq: Opt[int] = NOT_SET,
        number: Opt[str] = NOT_SET,
        asfuid: Opt[str] = NOT_SET,
        created: Opt[datetime.datetime] = NOT_SET,
        phase: Opt[sql.ReleasePhase] = NOT_SET,
        parent_name: Opt[str | None] = NOT_SET,
        description: Opt[str | None] = NOT_SET,
        _release: bool = False,
        _parent: bool = False,
        _child: bool = False,
    ) -> Query[sql.Revision]:
        query = sqlmodel.select(sql.Revision)

        if is_defined(name):
            query = query.where(sql.Revision.name == name)
        if is_defined(release_name):
            query = query.where(sql.Revision.release_name == release_name)
        if is_defined(seq):
            query = query.where(sql.Revision.seq == seq)
        if is_defined(number):
            query = query.where(sql.Revision.number == number)
        if is_defined(asfuid):
            query = query.where(sql.Revision.asfuid == asfuid)
        if is_defined(created):
            query = query.where(sql.Revision.created == created)
        if is_defined(phase):
            query = query.where(sql.Revision.phase == phase)
        if is_defined(parent_name):
            query = query.where(sql.Revision.parent_name == parent_name)
        if is_defined(description):
            query = query.where(sql.Revision.description == description)

        if _release:
            query = query.options(joined_load(sql.Revision.release))
        if _parent:
            query = query.options(joined_load(sql.Revision.parent))
        if _child:
            query = query.options(joined_load(sql.Revision.child))

        return Query(self, query)

    def ssh_key(
        self,
        fingerprint: Opt[str] = NOT_SET,
        key: Opt[str] = NOT_SET,
        asf_uid: Opt[str] = NOT_SET,
    ) -> Query[sql.SSHKey]:
        query = sqlmodel.select(sql.SSHKey)

        if is_defined(fingerprint):
            query = query.where(sql.SSHKey.fingerprint == fingerprint)
        if is_defined(key):
            query = query.where(sql.SSHKey.key == key)
        if is_defined(asf_uid):
            query = query.where(sql.SSHKey.asf_uid == asf_uid)

        return Query(self, query)

    def task(
        self,
        id: Opt[int] = NOT_SET,
        status: Opt[sql.TaskStatus] = NOT_SET,
        task_type: Opt[str] = NOT_SET,
        task_args: Opt[Any] = NOT_SET,
        asf_uid: Opt[str] = NOT_SET,
        added: Opt[datetime.datetime] = NOT_SET,
        started: Opt[datetime.datetime | None] = NOT_SET,
        pid: Opt[int | None] = NOT_SET,
        completed: Opt[datetime.datetime | None] = NOT_SET,
        result: Opt[Any | None] = NOT_SET,
        error: Opt[str | None] = NOT_SET,
        project_name: Opt[str | None] = NOT_SET,
        version_name: Opt[str | None] = NOT_SET,
        revision_number: Opt[str | None] = NOT_SET,
        primary_rel_path: Opt[str | None] = NOT_SET,
    ) -> Query[sql.Task]:
        query = sqlmodel.select(sql.Task)

        if is_defined(id):
            query = query.where(sql.Task.id == id)
        if is_defined(status):
            query = query.where(sql.Task.status == status)
        if is_defined(task_type):
            query = query.where(sql.Task.task_type == task_type)
        if is_defined(task_args):
            query = query.where(sql.Task.task_args == task_args)
        if is_defined(asf_uid):
            query = query.where(sql.Task.asf_uid == asf_uid)
        if is_defined(added):
            query = query.where(sql.Task.added == added)
        if is_defined(started):
            query = query.where(sql.Task.started == started)
        if is_defined(pid):
            query = query.where(sql.Task.pid == pid)
        if is_defined(completed):
            query = query.where(sql.Task.completed == completed)
        if is_defined(result):
            query = query.where(sql.Task.result == result)
        if is_defined(error):
            query = query.where(sql.Task.error == error)
        if is_defined(project_name):
            query = query.where(sql.Task.project_name == project_name)
        if is_defined(version_name):
            query = query.where(sql.Task.version_name == version_name)
        if is_defined(revision_number):
            query = query.where(sql.Task.revision_number == revision_number)
        if is_defined(primary_rel_path):
            query = query.where(sql.Task.primary_rel_path == primary_rel_path)

        return Query(self, query)

    def text_value(
        self,
        ns: Opt[str] = NOT_SET,
        key: Opt[str] = NOT_SET,
        value: Opt[str] = NOT_SET,
    ) -> Query[sql.TextValue]:
        query = sqlmodel.select(sql.TextValue)

        if is_defined(ns):
            query = query.where(sql.TextValue.ns == ns)
        if is_defined(key):
            query = query.where(sql.TextValue.key == key)
        if is_defined(value):
            query = query.where(sql.TextValue.value == value)

        return Query(self, query)


async def create_async_engine(app_config: type[config.AppConfig]) -> sqlalchemy.ext.asyncio.AsyncEngine:
    absolute_db_path = os.path.join(app_config.STATE_DIR, app_config.SQLITE_DB_PATH)
    # Three slashes are required before either a relative or absolute path
    sqlite_url = f"sqlite+aiosqlite:///{absolute_db_path}"
    # Use aiosqlite for async SQLite access
    engine = sqlalchemy.ext.asyncio.create_async_engine(
        sqlite_url,
        connect_args={
            "check_same_thread": False,
            "timeout": 30,
        },
    )

    # Set SQLite pragmas for better performance
    # Use 64 MB for the cache_size, and 5000ms for busy_timeout
    async with engine.begin() as conn:
        await conn.execute(sqlalchemy.text("PRAGMA journal_mode=WAL"))
        await conn.execute(sqlalchemy.text("PRAGMA synchronous=NORMAL"))
        await conn.execute(sqlalchemy.text("PRAGMA cache_size=-64000"))
        await conn.execute(sqlalchemy.text("PRAGMA foreign_keys=ON"))
        await conn.execute(sqlalchemy.text("PRAGMA busy_timeout=5000"))
        await conn.execute(sqlalchemy.text("PRAGMA strict=ON"))

    return engine


def ensure_session(caller_data: Session | None) -> Session | contextlib.nullcontext[Session]:
    if caller_data is None:
        return session()
    return contextlib.nullcontext(caller_data)


async def get_project_release_policy(data: Session, project_name: str) -> sql.ReleasePolicy | None:
    """Fetch the ReleasePolicy for a project."""
    project = await data.project(name=project_name, status=sql.ProjectStatus.ACTIVE, _release_policy=True).demand(
        RuntimeError(f"Project {project_name} not found")
    )
    return project.release_policy


def init_database(app: base.QuartApp) -> None:
    """
    Creates and initializes the database for a QuartApp.

    The database is created and an AsyncSession is registered as extension for the app.
    Any pending migrations are executed.
    """

    @app.before_serving
    async def create() -> None:
        global _global_atr_engine, _global_atr_sessionmaker

        app_config = config.get()
        engine = await create_async_engine(app_config)
        _global_atr_engine = engine

        _global_atr_sessionmaker = sqlalchemy.ext.asyncio.async_sessionmaker(
            bind=engine, class_=Session, expire_on_commit=False
        )

        # Run any pending migrations on startup
        log.info("Applying database migrations via init_database...")
        alembic_ini_path = os.path.join(app_config.PROJECT_ROOT, "alembic.ini")
        alembic_cfg = alembic_config.Config(alembic_ini_path)

        # Construct synchronous URLs
        absolute_db_path = os.path.join(app_config.STATE_DIR, app_config.SQLITE_DB_PATH)
        sync_sqlalchemy_url = f"sqlite:///{absolute_db_path}"
        log.info(f"Setting Alembic URL for command: {sync_sqlalchemy_url}")
        alembic_cfg.set_main_option("sqlalchemy.url", sync_sqlalchemy_url)

        # Ensure that Alembic finds the migrations directory relative to project root
        migrations_dir_path = os.path.join(app_config.PROJECT_ROOT, "migrations")
        log.info(f"Setting Alembic script_location for command: {migrations_dir_path}")
        alembic_cfg.set_main_option("script_location", migrations_dir_path)

        try:
            log.info("Running alembic upgrade head...")
            command.upgrade(alembic_cfg, "head")
            log.info("Database migrations applied successfully")
        except Exception:
            log.exception("Failed to apply database migrations during startup")
            raise

        try:
            log.info("Running alembic check...")
            command.check(alembic_cfg)
            log.info("Alembic check passed: DB schema matches models")
        except Exception:
            log.exception("Failed to check database migrations during startup")
            raise


async def init_database_for_worker() -> None:
    global _global_atr_engine, _global_atr_sessionmaker

    log.info(f"Creating database for worker {os.getpid()}")
    engine = await create_async_engine(config.get())
    _global_atr_engine = engine
    _global_atr_sessionmaker = sqlalchemy.ext.asyncio.async_sessionmaker(
        bind=engine, class_=Session, expire_on_commit=False
    )


def is_defined[T](v: T | NotSet) -> TypeGuard[T]:
    return not isinstance(v, NotSet)


def is_undefined(v: object | NotSet) -> TypeGuard[NotSet]:
    return isinstance(v, NotSet)


def joined_load(*entities: Any) -> orm.strategy_options._AbstractLoad:
    """Eagerly load the given entities from the query using joinedload."""
    validated_entities = []
    for entity in entities:
        if not isinstance(entity, orm.InstrumentedAttribute):
            raise ValueError(f"Object must be an orm.InstrumentedAttribute, got: {type(entity)}")
        validated_entities.append(entity)
    return orm.joinedload(*validated_entities)


def joined_load_nested(parent: Any, *descendants: Any) -> orm.strategy_options._AbstractLoad:
    """Eagerly load the given nested entities from the query using joinedload."""
    if not isinstance(parent, orm.InstrumentedAttribute):
        raise ValueError(f"Parent must be an orm.InstrumentedAttribute, got: {type(parent)}")
    for descendant in descendants:
        if not isinstance(descendant, orm.InstrumentedAttribute):
            raise ValueError(f"Descendant must be an orm.InstrumentedAttribute, got: {type(descendant)}")
    return orm.joinedload(parent).joinedload(*descendants)


@contextlib.contextmanager
def log_queries() -> Iterator[None]:
    """A context manager to temporarily enable global query logging."""
    global global_log_query
    original_global_log_query_state = global_log_query
    global_log_query = True
    try:
        yield
    finally:
        global_log_query = original_global_log_query_state


# async def recent_tasks(data: Session, release_name: str, file_path: str, modified: int) -> dict[str, models.Task]:
#     """Get the most recent task for each task type for a specific file."""
#     tasks = await data.task(
#         release_name=release_name,
#         path=str(file_path),
#         modified=modified,
#     ).all()
#
#     # Group by task_type and keep the most recent one
#     # We use the highest id to determine the most recent task
#     recent_tasks: dict[str, models.Task] = {}
#     for task in tasks:
#         # If we haven't seen this task type before or if this task is newer
#         if (task.task_type.value not in recent_tasks) or (task.id > recent_tasks[task.task_type.value].id):
#             recent_tasks[task.task_type.value] = task
#
#     return recent_tasks


def select_in_load(*entities: Any) -> orm.strategy_options._AbstractLoad:
    """Eagerly load the given entities from the query."""
    validated_entities = []
    for entity in entities:
        if not isinstance(entity, orm.InstrumentedAttribute):
            raise ValueError(f"Object must be an orm.InstrumentedAttribute, got: {type(entity)}")
        validated_entities.append(entity)
    return orm.selectinload(*validated_entities)


def select_in_load_nested(parent: Any, *descendants: Any) -> orm.strategy_options._AbstractLoad:
    """Eagerly load the given nested entities from the query."""
    if not isinstance(parent, orm.InstrumentedAttribute):
        raise ValueError(f"Parent must be an orm.InstrumentedAttribute, got: {type(parent)}")
    for descendant in descendants:
        if not isinstance(descendant, orm.InstrumentedAttribute):
            raise ValueError(f"Descendant must be an orm.InstrumentedAttribute, got: {type(descendant)}")
    result = orm.selectinload(parent)
    for descendant in descendants:
        result = result.selectinload(descendant)
    return result


def session(log_queries: bool | None = None) -> Session:
    """Create a new asynchronous database session."""
    # FIXME: occasionally you see this in the console output
    # <sys>:0: SAWarning: The garbage collector is trying to clean up non-checked-in connection <AdaptedConnection
    # <Connection(Thread-291, started daemon 138838634661440)>>, which will be dropped, as it cannot be safely
    # terminated. Please ensure that SQLAlchemy pooled connections are returned to the pool explicitly, either by
    # calling ``close()`` or by using appropriate context managers to manage their lifecycle.

    # Not fully clear where this is coming from, but we could experiment by returning a session like that:
    # async def session() -> AsyncGenerator[Session, None]:
    #     async with _global_atr_sessionmaker() as session:
    #         yield session

    # from FastAPI documentation: https://fastapi-users.github.io/fastapi-users/latest/configuration/databases/sqlalchemy/

    global _global_atr_sessionmaker
    if _global_atr_sessionmaker is None:
        raise RuntimeError("Call db.init_database or db.init_database_for_worker first, before calling db.session")

    if log_queries is not None:
        session_instance = util.validate_as_type(_global_atr_sessionmaker(log_queries=log_queries), Session)
    else:
        session_instance = util.validate_as_type(_global_atr_sessionmaker(), Session)
    return session_instance


def session_commit_function[**P, R](
    func: Callable[Concatenate[Session, P], Awaitable[R]],
) -> Callable[P, Awaitable[R]]:
    @functools.wraps(func)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        async with session() as data:
            async with data.begin():
                return await func(data, *args, **kwargs)

    return wrapper


def session_function[**P, R](
    func: Callable[Concatenate[Session, P], Awaitable[R]],
) -> Callable[P, Awaitable[R]]:
    @functools.wraps(func)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        async with session() as data:
            return await func(data, *args, **kwargs)

    return wrapper


async def shutdown_database() -> None:
    if _global_atr_engine:
        log.info("Closing database")
        await _global_atr_engine.dispose()
    else:
        log.info("No database to close")
