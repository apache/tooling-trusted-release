#!/usr/bin/env python3
"""Generic endpoints for ASFQuart"""

import secrets
import urllib
import time

import quart
import aiohttp

import asfquart  # implies .session


# These are the ASF OAuth URLs for init and verification. Used for setup_oauth()
OAUTH_URL_INIT = "https://oauth.apache.org/auth-oidc?state=%s&redirect_uri=%s"
OAUTH_URL_CALLBACK = "https://oauth.apache.org/token-oidc?code=%s"
DEFAULT_OAUTH_URI = "/auth"


def setup_oauth(app, uri=DEFAULT_OAUTH_URI, workflow_timeout: int = 900):
    """Sets up a generic ASF OAuth endpoint for the given app. The default URI is /auth, and the
    default workflow timeout is 900 seconds (15 min), within which the OAuth login must
    be completed. The OAuth endpoint handles everything related to logging in and out via OAuth,
    and has the following actions:

    - /auth?login  - Initializes an OAuth login
    - /auth?login=/foo - Same as above, but redirects to /foo on successful login
    - /auth?logout - Clears a user session, logging them out
    - /auth  - Shows the user's credentials if logged in, 404 otherwise.

    This generic route expects the Host: header of the request to be accurate, which means setting
    "ProxyPreserveHost On" in your httpd config if proxying.
    """

    pending_states = {}  # keeps track of pending states and their expiry

    @app.route(uri)
    async def oauth_endpoint():
        # Init oauth login
        login_uri = quart.request.args.get("login")
        if login_uri and login_uri.endswith("?"):
            # for some reason I don't understand, quart keeps adding a '?' to the uri
            login_uri = login_uri.removeprefix("?")
        logout_uri = quart.request.args.get("logout")
        if login_uri or quart.request.query_string == b"login":
            state = secrets.token_hex(16)
            # Save the time we initialized this state and the optional login redirect URI
            pending_states[state] = [time.time(), login_uri]
            callback_host = quart.request.host_url.replace("http://", "https://")  # Enforce HTTPS
            callback_url = urllib.parse.urljoin(  # NOTE: the uri MUST start with a single forward slash!
                callback_host,
                f"{uri}?state={state}",
            )
            redirect_url = OAUTH_URL_INIT % (state, urllib.parse.quote(callback_url))
            return quart.redirect(redirect_url)

        # Log out
        elif logout_uri or quart.request.query_string == b"logout":
            asfquart.session.clear()
            if logout_uri:  # if called with /auth=logout=/foo, redirect to /foo
                return quart.redirect(logout_uri)
            return quart.Response(
                status=200,
                response=f"Client session removed, goodbye!\n",
            )
        else:
            code = quart.request.args.get("code")
            state = quart.request.args.get("state")
            if code and state:  # Callback from oauth, complete flow.
                if state not in pending_states or pending_states[state][0] < (time.time() - workflow_timeout):
                    pending_states.pop(state, None)  # safe pop
                    return quart.Response(
                        status=403,
                        response=f"Invalid or expired OAuth state provided. OAuth workflows must be completed within {workflow_timeout} seconds.\n",
                    )
                redirect_uri = pending_states[state][1]
                pending_states.pop(
                    state
                )  # Pop the state from pending. We do this straight away to avoid timing attacks
                ct = aiohttp.client.ClientTimeout(sock_read=15)
                async with aiohttp.client.ClientSession(timeout=ct) as session:
                    rv = await session.get(OAUTH_URL_CALLBACK % code)
                    assert rv.status == 200, "Could not verify oauth response."
                    oauth_data = await rv.json()
                    asfquart.session.write(oauth_data)
                if redirect_uri:  # if called with /auth=login=/foo, redirect to /foo
                    # If SameSite is set, we cannot redirect with a 30x response, as that may invalidate the set-cookie
                    # instead, we issue a 200 Okay with a Refresh header, instructing the browser to immediately go
                    # someplace else. This counts as a samesite request.
                    return quart.Response(
                        status=200,
                        response=f"Successfully logged in! Welcome, {oauth_data['uid']}\n",
                        headers={"Refresh": f"0; url={redirect_uri}"},
                    )
                # Otherwise, just say hi
                return quart.Response(
                    status=200,
                    response=f"""
                    Successfully signed in! Welcome, {oauth_data["uid"]}
                    """,
                )
            else:  # Just spit out existing session if it's there
                client_session = await asfquart.session.read()
                if isinstance(client_session, asfquart.session.ClientSession):
                    return client_session
                return quart.Response(
                    status=404,
                    response=f"No active session found.\n",
                )


def enforce_login(app, redirect_uri=DEFAULT_OAUTH_URI):
    """Enforces redirect to the auth provider (if enabled) when a client tries to access a restricted page
    without being logged in. Only redirects if there is no active user session. On success, the client
    is redirected back to the origin page that was restricted. If it is still restricted, the client
    will instead see an error message."""
    import asfquart.auth

    @app.errorhandler(asfquart.auth.AuthenticationFailed)
    async def auth_redirect(error):
        # If we have no client session (and X-No-Redirect is not set), redirect to auth flow
        if (
            "x-no-redirect" not in quart.request.headers
            and not quart.request.authorization
            and not await asfquart.session.read()
        ):
            return quart.redirect(f"{redirect_uri}?login={quart.request.full_path}")
        # If we have a session, but still no access, just say so in plain text.
        return quart.Response(status=error.errorcode, response=error.message)
