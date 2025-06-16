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

import collections
import dataclasses
from typing import Final

import ldap3
import ldap3.utils.conv as conv
import ldap3.utils.dn as dn

LDAP_SEARCH_BASE: Final[str] = "ou=people,dc=apache,dc=org"
LDAP_SERVER_HOST: Final[str] = "ldap-eu.apache.org"


# We use a dataclass to support ldap3.Connection objects
@dataclasses.dataclass
class SearchParameters:
    uid_query: str | None = None
    email_query: str | None = None
    bind_dn_from_config: str | None = None
    bind_password_from_config: str | None = None
    results_list: list[dict[str, str | list[str]]] = dataclasses.field(default_factory=list)
    err_msg: str | None = None
    srv_info: str | None = None
    detail_err: str | None = None
    connection: ldap3.Connection | None = None
    email_only: bool = False


def parse_dn(dn_string: str) -> dict[str, list[str]]:
    parsed = collections.defaultdict(list)
    parts = dn.parse_dn(dn_string)
    for part in parts:
        for attr, value in part:
            parsed[attr].append(value)
    return dict(parsed)


def search(params: SearchParameters) -> None:
    try:
        _search_core(params)
    except Exception as e:
        params.err_msg = f"An unexpected error occurred: {e!s}"
        params.detail_err = f"Details: {e.args}"
    finally:
        if params.connection and params.connection.bound:
            try:
                params.connection.unbind()
            except Exception:
                ...


def _search_core(params: SearchParameters) -> None:
    params.results_list = []
    params.err_msg = None
    params.srv_info = None
    params.detail_err = None
    params.connection = None

    server = ldap3.Server(LDAP_SERVER_HOST, use_ssl=True, get_info=ldap3.ALL)
    params.srv_info = repr(server)

    if params.bind_dn_from_config and params.bind_password_from_config:
        params.connection = ldap3.Connection(
            server, user=params.bind_dn_from_config, password=params.bind_password_from_config, auto_bind=True
        )
    else:
        params.connection = ldap3.Connection(server, auto_bind=True)

    filters: list[str] = []
    if params.uid_query:
        if params.uid_query == "*":
            filters.append("(uid=*)")
        else:
            filters.append(f"(uid={conv.escape_filter_chars(params.uid_query)})")

    if params.email_query:
        escaped_email = conv.escape_filter_chars(params.email_query)
        if params.email_query.endswith("@apache.org"):
            filters.append(f"(mail={escaped_email})")
        else:
            filters.append(f"(asf-altEmail={escaped_email})")

    if not filters:
        params.err_msg = "Please provide a UID or an email address to search."
        return

    search_filter = f"(&{''.join(filters)})" if (len(filters) > 1) else filters[0]

    if not params.connection:
        params.err_msg = "LDAP Connection object not established or auto_bind failed."
        return

    email_attributes = ["uid", "mail", "asf-altEmail", "asf-committer-email"]
    attributes = email_attributes if params.email_only else ldap3.ALL_ATTRIBUTES
    params.connection.search(
        search_base=LDAP_SEARCH_BASE,
        search_filter=search_filter,
        attributes=attributes,
    )
    for entry in params.connection.entries:
        result_item: dict[str, str | list[str]] = {"dn": entry.entry_dn}
        result_item.update(entry.entry_attributes_as_dict)
        params.results_list.append(result_item)

    if (not params.results_list) and (not params.err_msg):
        params.err_msg = "No results found for the given criteria."
