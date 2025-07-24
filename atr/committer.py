#!/usr/bin/env python3
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

import re
from typing import Any

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
        self._get_committer_details()

        member_list = self._get_group_membership(LDAP_MEMBER_BASE, "memberUid", 100)
        self.isMember = self.user in member_list

        chair_list = self._get_group_membership(LDAP_CHAIRS_BASE, "member", 100)
        self.isChair = self.dn in chair_list

        root_list = self._get_group_membership(LDAP_ROOT_BASE, "member", 3)
        self.isRoot = self.dn in root_list

        tooling_list = self._get_group_membership(LDAP_TOOLING_BASE, "member", 1)
        is_tooling = self.dn in tooling_list

        self.pmcs = self._get_project_memberships(LDAP_OWNER_FILTER)
        self.projects = self._get_project_memberships(LDAP_MEMBER_FILTER)

        if is_tooling:
            self.pmcs.append("tooling")
            self.projects.append("tooling")

        return self.__dict__

    def _get_committer_details(self) -> None:
        try:
            result = ldap.search_single(
                ldap_bind_dn=self.__bind_dn,
                ldap_bind_password=self.__bind_password,
                ldap_base=self.dn,
                ldap_scope="BASE",
            )
            log.info(f"LDAP result: {result} for {self.dn}")
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

    def _get_group_membership(self, ldap_base: str, attribute: str, min_members: int = 0) -> list:
        try:
            result = ldap.search_single(
                ldap_bind_dn=self.__bind_dn,
                ldap_bind_password=self.__bind_password,
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

    def _get_project_memberships(self, ldap_filter: str) -> list[str]:
        try:
            result = ldap.search_single(
                ldap_bind_dn=self.__bind_dn,
                ldap_bind_password=self.__bind_password,
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
