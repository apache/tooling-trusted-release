#!/usr/bin/env python3

import time

import pytest
import quart
import asfquart


@pytest.mark.asyncio
@pytest.mark.session
async def test_sessions():
    app = asfquart.construct("foobar")
    quart.session = {app.app_id: {"uts": time.time(), "uid": "bar"}}
    my_session = await asfquart.session.read()
    assert my_session, "Was expecting a session, but got nothing in return"
    assert my_session.uid == "bar", f"session value 'uid' should be 'bar', but was '{my_session.uid}'"
