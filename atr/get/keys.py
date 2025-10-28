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

"""keys.py"""

import datetime

import asfquart as asfquart
import quart
import werkzeug.wrappers.response as response

import atr.blueprints.get as get
import atr.db as db
import atr.route as route
import atr.shared as shared
import atr.storage as storage
import atr.template as template
import atr.util as util
import atr.web as web


@get.committer("/keys/add")
async def add(session: web.Committer) -> str:
    """Add a new public signing key to the user's account."""
    return await shared.keys.add(session)


@get.committer("/keys/details/<fingerprint>")
async def details(session: web.Committer, fingerprint: str) -> str | response.Response:
    """Display details for a specific OpenPGP key."""
    return await shared.keys.details(session, fingerprint)


@route.committer("/keys/export/<committee_name>")
async def export(session: route.CommitterSession, committee_name: str) -> web.TextResponse:
    """Export a KEYS file for a specific committee."""
    async with storage.write() as write:
        wafc = write.as_foundation_committer()
        keys_file_text = await wafc.keys.keys_file_text(committee_name)

    return web.TextResponse(keys_file_text)


@route.committer("/keys")
async def keys(session: route.CommitterSession) -> str:
    """View all keys associated with the user's account."""
    committees_to_query = list(set(session.committees + session.projects))

    delete_form = await shared.keys.DeleteKeyForm.create_form()
    update_committee_keys_form = await shared.keys.UpdateCommitteeKeysForm.create_form()

    async with db.session() as data:
        user_keys = await data.public_signing_key(apache_uid=session.uid.lower(), _committees=True).all()
        user_ssh_keys = await data.ssh_key(asf_uid=session.uid).all()
        user_committees_with_keys = await data.committee(name_in=committees_to_query, _public_signing_keys=True).all()
    for key in user_keys:
        key.committees.sort(key=lambda c: c.name)

    status_message = quart.request.args.get("status_message")
    status_type = quart.request.args.get("status_type")

    return await template.render(
        "keys-review.html",
        asf_id=session.uid,
        user_keys=user_keys,
        user_ssh_keys=user_ssh_keys,
        committees=user_committees_with_keys,
        algorithms=shared.algorithms,
        status_message=status_message,
        status_type=status_type,
        now=datetime.datetime.now(datetime.UTC),
        delete_form=delete_form,
        update_committee_keys_form=update_committee_keys_form,
        email_from_key=util.email_from_uid,
        committee_is_standing=util.committee_is_standing,
    )


@get.committer("/keys/ssh/add")
async def ssh_add(session: web.Committer) -> response.Response | str:
    """Add a new SSH key to the user's account."""
    return await shared.keys.ssh_add(session)


@get.committer("/keys/upload")
async def upload(session: web.Committer) -> str:
    """Upload a KEYS file containing multiple OpenPGP keys."""
    return await shared.keys.upload(session)
