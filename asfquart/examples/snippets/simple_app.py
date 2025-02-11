#!/usr/bin/env python3
"""Simple ASFQuart server example - one file for everything"""

import asfquart
import asfquart.auth
import asfquart.generics
import asfquart.session


def my_app():
    # Construct the base app. The /oauth gateway is enabled by default.
    # To disable it, use construct("my_app", oauth=False)
    app = asfquart.construct("my_simple_app")

    # Default homepage
    @app.route("/")
    async def homepage():
        return "Hello!"

    # the /secret URI, which shows the session data or forces a login
    @app.route("/secret")
    @asfquart.auth.require(asfquart.auth.Requirements.committer)
    async def secret_page():
        return await asfquart.session.read()

    # Authentication failures redirect to login flow.
    asfquart.generics.enforce_login(app)

    app.run(port=8000)


if __name__ == "__main__":
    my_app()
