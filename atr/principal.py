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

# Derived from apache/infrastructure-oauth/app/lib/ldap.py

import asyncio
import re
import time
from typing import Any, Final

import asfquart.session as session

import atr.config as config
import atr.ldap as ldap
import atr.log as log

LDAP_CHAIRS_BASE = "cn=pmc-chairs,ou=groups,ou=services,dc=apache,dc=org"
LDAP_DN = "uid=%s,ou=people,dc=apache,dc=org"
LDAP_MEMBER_BASE = "cn=member,ou=groups,dc=apache,dc=org"
LDAP_MEMBER_FILTER = "(|(memberUid=%s)(member=uid=%s,ou=people,dc=apache,dc=org))"
LDAP_OWNER_FILTER = "(|(ownerUid=%s)(owner=uid=%s,ou=people,dc=apache,dc=org))"
LDAP_PEOPLE_BASE = "ou=people,dc=apache,dc=org"
LDAP_PMCS_BASE = "ou=project,ou=groups,dc=apache,dc=org"
LDAP_ROOT_BASE = "cn=infrastructure-root,ou=groups,ou=services,dc=apache,dc=org"
LDAP_TOOLING_BASE = "cn=tooling,ou=groups,ou=services,dc=apache,dc=org"


class AuthenticationError(Exception):
    """Simple exception with a message and an optional origin exception (WIP)"""

    def __init__(self, message, origin=None):
        super().__init__(message)
        self.origin = origin


class CommitterError(Exception):
    """Simple exception with a message and an optional origin exception (WIP)"""

    def __init__(self, message, origin=None):
        super().__init__(message)
        self.origin = origin


def attr_to_list(attr):
    """Converts a list of bytestring attribute values to a unique list of strings"""
    return list(set([value for value in attr or []]))


class Committer:
    """Verifies and loads a committers credentials via LDAP"""

    def __init__(self, user: str) -> None:
        if not re.match(r"^[-_a-z0-9]+$", user):
            raise CommitterError("Invalid characters in User ID. Only lower-case alphanumerics, '-' and '_' allowed.")
        self.user = user
        self.uid = user
        self.dn = LDAP_DN % user
        self.email = f"{user}@apache.org"
        self.fullname: str = ""
        self.emails: list[str] = []
        self.altemails: list[str] = []
        self.isMember: bool = False
        self.isChair: bool = False
        self.isRoot: bool = False
        self.pmcs: list[str] = []
        self.projects: list[str] = []

        self.__bind_dn, self.__bind_password = self._get_ldap_bind_dn_and_password()

    def verify(self) -> dict[str, Any]:
        with ldap.Search(self.__bind_dn, self.__bind_password) as ldap_search:
            start = time.perf_counter_ns()
            self._get_committer_details(ldap_search)
            finish = time.perf_counter_ns()
            log.info(f"Took {finish - start:,} ns to get committer details")

            start = time.perf_counter_ns()
            member_list = self._get_group_membership(ldap_search, LDAP_MEMBER_BASE, "memberUid", 100)
            self.isMember = self.user in member_list
            finish = time.perf_counter_ns()
            log.info(f"Took {finish - start:,} ns to get member list")

            start = time.perf_counter_ns()
            chair_list = self._get_group_membership(ldap_search, LDAP_CHAIRS_BASE, "member", 100)
            self.isChair = self.dn in chair_list
            finish = time.perf_counter_ns()
            log.info(f"Took {finish - start:,} ns to get chair list")

            start = time.perf_counter_ns()
            root_list = self._get_group_membership(ldap_search, LDAP_ROOT_BASE, "member", 3)
            self.isRoot = self.dn in root_list
            finish = time.perf_counter_ns()
            log.info(f"Took {finish - start:,} ns to get root list")

            start = time.perf_counter_ns()
            tooling_list = self._get_group_membership(ldap_search, LDAP_TOOLING_BASE, "member", 1)
            is_tooling = self.dn in tooling_list
            finish = time.perf_counter_ns()
            log.info(f"Took {finish - start:,} ns to get tooling list")

            start = time.perf_counter_ns()
            self.pmcs = self._get_project_memberships(ldap_search, LDAP_OWNER_FILTER)
            self.projects = self._get_project_memberships(ldap_search, LDAP_MEMBER_FILTER)
            finish = time.perf_counter_ns()
            log.info(f"Took {finish - start:,} ns to get project memberships")

            if is_tooling:
                self.pmcs.append("tooling")
                self.projects.append("tooling")

        return self.__dict__

    def _get_committer_details(self, ldap_search: ldap.Search) -> None:
        try:
            result = ldap_search.search(
                ldap_base=self.dn,
                ldap_scope="BASE",
            )
            if not (result and len(result) == 1):
                raise CommitterError(f"User {self.user!r} not found in LDAP")
        except CommitterError:
            raise
        except Exception as ex:
            log.exception(f"An unknown error occurred while fetching user details: {ex!s}")
            raise CommitterError("An unknown error occurred while fetching user details.") from ex

        data = result[0]
        if data.get("asf-banned"):
            raise CommitterError(
                "This account has been administratively locked. Please contact root@apache.org for further details."
            )

        fn = data.get("cn")
        if not (isinstance(fn, list) and (len(fn) == 1)):
            raise CommitterError("Common backend assertions failed, LDAP corruption?")
        self.fullname = fn[0]
        self.emails = attr_to_list(data.get("mail"))
        self.altemails = attr_to_list(data.get("asf-altEmail"))

    def _get_group_membership(
        self, ldap_search: ldap.Search, ldap_base: str, attribute: str, min_members: int = 0
    ) -> list:
        try:
            result = ldap_search.search(
                ldap_base=ldap_base,
                ldap_scope="BASE",
            )
            if not (result and (len(result) == 1)):
                raise CommitterError("Common backend assertions failed, LDAP corruption?")
        except CommitterError:
            raise
        except Exception as ex:
            log.exception(f"An unknown error occurred while fetching group memberships from {ldap_base}: {ex!s}")
            raise CommitterError(
                f"An unknown error occurred while fetching group memberships from {ldap_base}."
            ) from ex

        members = result[0].get(attribute)
        if not isinstance(members, list):
            raise CommitterError("Common backend assertions failed, LDAP corruption?")
        if len(members) < min_members:
            raise CommitterError("Common backend assertions failed, LDAP corruption?")
        return members

    def _get_ldap_bind_dn_and_password(self) -> tuple[str, str]:
        conf = config.AppConfig()
        bind_dn = conf.LDAP_BIND_DN
        bind_password = conf.LDAP_BIND_PASSWORD
        if (not bind_dn) or (not bind_password):
            raise CommitterError("LDAP bind DN or password not set")
        return bind_dn, bind_password

    def _get_project_memberships(self, ldap_search: ldap.Search, ldap_filter: str) -> list[str]:
        try:
            result = ldap_search.search(
                ldap_base=LDAP_PMCS_BASE,
                ldap_scope="SUBTREE",
                ldap_query=ldap_filter % (self.user, self.user),
                ldap_attrs=["cn"],
            )
        except Exception as ex:
            log.exception(f"An unknown error occurred while fetching project memberships: {ex!s}")
            raise CommitterError("An unknown error occurred while fetching project memberships.") from ex

        projects = []
        for hit in result:
            if not isinstance(hit, dict):
                raise CommitterError("Common backend assertions failed, LDAP corruption?")
            pmc = hit.get("cn")
            if not (isinstance(pmc, list) and len(pmc) == 1):
                raise CommitterError("Common backend assertions failed, LDAP corruption?")
            project_name = pmc[0]
            if not (project_name and isinstance(project_name, str)):
                raise CommitterError("Common backend assertions failed, LDAP corruption?")
            projects.append(project_name)
        return projects


class Cache:
    def __init__(self, cache_for_at_most_seconds: int = 600):
        self.cache_for_at_most_seconds = cache_for_at_most_seconds
        self.last_refreshed: int | None = None
        self.member_of: dict[str, frozenset[str]] = {}
        self.participant_of: dict[str, frozenset[str]] = {}

    def outdated(self) -> bool:
        if self.last_refreshed is None:
            return True
        now = int(time.time())
        since_last_refresh = now - self.last_refreshed
        return since_last_refresh > self.cache_for_at_most_seconds


class AuthoriserASFQuart:
    def __init__(self):
        self.__cache = Cache()

    async def is_member_of(self, asf_uid: str, asfquart_session: session.ClientSession, committee_name: str) -> bool:
        await self.__cache_refresh(asf_uid, asfquart_session)
        return committee_name in self.__cache.member_of[asf_uid]

    async def is_participant_of(self, asf_uid: str, asfquart_session: session.ClientSession, project_name: str) -> bool:
        await self.__cache_refresh(asf_uid, asfquart_session)
        return project_name in self.__cache.participant_of[asf_uid]

    async def member_of(self, asf_uid: str, asfquart_session: session.ClientSession) -> frozenset[str]:
        await self.__cache_refresh(asf_uid, asfquart_session)
        return self.__cache.member_of[asf_uid]

    async def participant_of(self, asf_uid: str, asfquart_session: session.ClientSession) -> frozenset[str]:
        await self.__cache_refresh(asf_uid, asfquart_session)
        return self.__cache.participant_of[asf_uid]

    async def member_of_and_participant_of(
        self, asf_uid: str, asfquart_session: dict[str, Any]
    ) -> tuple[frozenset[str], frozenset[str]]:
        await self.__cache_refresh(asf_uid, asfquart_session)
        return self.__cache.member_of[asf_uid], self.__cache.participant_of[asf_uid]

    async def __cache_refresh(self, asf_uid: str, asfquart_session: dict[str, Any]) -> None:
        if not self.__cache.outdated():
            return
        # We do not check that the ASF UID is the same as the one in the session
        # It is the caller's responsibility to ensure this
        self.__cache.member_of[asf_uid] = frozenset(asfquart_session.get("pmcs", []))
        self.__cache.participant_of[asf_uid] = frozenset(asfquart_session.get("projects", []))
        self.__cache.last_refreshed = int(time.time())


class AuthoriserLDAP:
    def __init__(self):
        self.__cache = Cache()

    async def is_member_of(self, asf_uid: str, committee_name: str) -> bool:
        await self.__cache_refresh(asf_uid)
        return committee_name in self.__cache.member_of[asf_uid]

    async def is_participant_of(self, asf_uid: str, committee_name: str) -> bool:
        await self.__cache_refresh(asf_uid)
        return committee_name in self.__cache.participant_of[asf_uid]

    async def member_of(self, asf_uid: str) -> frozenset[str]:
        await self.__cache_refresh(asf_uid)
        return self.__cache.member_of[asf_uid]

    async def participant_of(self, asf_uid: str) -> frozenset[str]:
        await self.__cache_refresh(asf_uid)
        return self.__cache.participant_of[asf_uid]

    async def member_of_and_participant_of(self, asf_uid: str) -> tuple[frozenset[str], frozenset[str]]:
        await self.__cache_refresh(asf_uid)
        return self.__cache.member_of[asf_uid], self.__cache.participant_of[asf_uid]

    async def __cache_refresh(self, asf_uid: str) -> None:
        if not self.__cache.outdated():
            return
        try:
            c = Committer(asf_uid)
            await asyncio.to_thread(c.verify)
            self.__cache.member_of[asf_uid] = frozenset(c.pmcs)
            self.__cache.participant_of[asf_uid] = frozenset(c.projects)
            self.__cache.last_refreshed = int(time.time())
        except CommitterError as e:
            raise AuthenticationError(f"Failed to verify committer: {e}") from e


authoriser_asfquart: Final[AuthoriserASFQuart] = AuthoriserASFQuart()
authoriser_ldap: Final[AuthoriserLDAP] = AuthoriserLDAP()


class AuthorisationASFQuart:
    def __init__(self, authoriser: AuthoriserASFQuart, asfquart_session: session.ClientSession):
        # We provide and authenticate the ASF UID for the caller
        self.asfquart_session = asfquart_session
        self.authoriser = authoriser
        self.asf_uid = self.asfquart_session.get("uid")
        self.authenticated = True

    async def is_member_of(self, committee_name: str) -> bool:
        if self.asf_uid is None:
            return False
        return await self.authoriser.is_member_of(self.asf_uid, self.asfquart_session, committee_name)

    async def is_participant_of(self, committee_name: str) -> bool:
        if self.asf_uid is None:
            return False
        return await self.authoriser.is_participant_of(self.asf_uid, self.asfquart_session, committee_name)

    async def participant_of(self) -> frozenset[str]:
        if self.asf_uid is None:
            return frozenset()
        return await self.authoriser.participant_of(self.asf_uid, self.asfquart_session)

    async def member_of(self) -> frozenset[str]:
        if self.asf_uid is None:
            return frozenset()
        return await self.authoriser.member_of(self.asf_uid, self.asfquart_session)


class AuthorisationLDAP:
    def __init__(self, authoriser: AuthoriserLDAP, asf_uid: str | None = None):
        # The caller must provide an already authenticated ASF UID
        self.authoriser = authoriser
        self.asf_uid = asf_uid
        self.authenticated = asf_uid is None

    async def is_member_of(self, committee_name: str) -> bool:
        if self.asf_uid is None:
            return False
        return await self.authoriser.is_member_of(self.asf_uid, committee_name)

    async def is_participant_of(self, committee_name: str) -> bool:
        if self.asf_uid is None:
            return False
        return await self.authoriser.is_participant_of(self.asf_uid, committee_name)

    async def participant_of(self) -> frozenset[str]:
        if self.asf_uid is None:
            return frozenset()
        return await self.authoriser.participant_of(self.asf_uid)

    async def member_of(self) -> frozenset[str]:
        if self.asf_uid is None:
            return frozenset()
        return await self.authoriser.member_of(self.asf_uid)


class AsyncObject:
    async def __new__(cls, *a, **kw):
        instance = super().__new__(cls)
        await instance.__init__(*a, **kw)
        return instance

    async def __init__(self):
        pass


class Authorisation(AsyncObject):
    class __ArgumentNoneType:
        pass

    __ArgumentNone = __ArgumentNoneType()

    async def __init__(self, asf_uid: str | None | __ArgumentNoneType = __ArgumentNone):
        match asf_uid:
            case Authorisation.__ArgumentNone:
                asfquart_session = await session.read()
                if asfquart_session is None:
                    raise AuthenticationError("No ASFQuart session found")
                self.__authoriser = AuthoriserASFQuart()
                self.__authorisation = AuthorisationASFQuart(self.__authoriser, asfquart_session)
            case str() | None:
                self.__authoriser = AuthoriserLDAP()
                self.__authorisation = AuthorisationLDAP(self.__authoriser, asf_uid)

    @property
    def asf_uid(self) -> str | None:
        return self.__authorisation.asf_uid

    @property
    def is_asfquart_session(self) -> bool:
        match self.__authorisation:
            case AuthorisationASFQuart():
                return True
            case AuthorisationLDAP():
                return False

    @property
    def is_authenticated(self) -> bool:
        return self.__authorisation.authenticated

    def is_committer(self) -> bool:
        return self.__authorisation.asf_uid is not None

    async def is_member_of(self, committee_name: str) -> bool:
        # TODO: This is a workaround for a bug
        if self.__authorisation.asf_uid in {"sbp", "tn", "wave"}:
            if committee_name == "tooling":
                return True
        return await self.__authorisation.is_member_of(committee_name)

    async def is_participant_of(self, committee_name: str) -> bool:
        return await self.__authorisation.is_participant_of(committee_name)

    async def participant_of(self) -> frozenset[str]:
        return await self.__authorisation.participant_of()

    async def member_of(self) -> frozenset[str]:
        return await self.__authorisation.member_of()
