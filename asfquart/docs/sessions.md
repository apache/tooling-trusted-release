# Session handling

OAuth user sessions can be accessed through the `asfquart.session` component, and are encrypted 
to ensure authenticity.

The login and logout flow is automatically handled by asfquart, unless explicitly told not to, 
and sessions can be accessed and modified as needed:

~~~python

@asfquart.auth.require  # Implicitly require a valid (non-empty) session
async def endpoint_with_session():
   session = await asfquart.session.read()  # Read user session dict
   session["foobar"] = 42
   asfquart.session.write(session)  # Store our changes in the user session
~~~

Session timeouts can be handled by passing the `expiry_time` argument to the `read()` call:

~~~python
session = await asfquart.session.read(expiry_time=24*3600)  # Require a session that has been accessed in the past 24 hours.
assert session, "No session found or session expired"  # If too old or not found, read() returns None
~~~


## Role account management via declared PAT handler
Role accounts (or regular users) can access asfquart apps by using a bearer token, so long as a personal app token (PAT) handler 
is declared:

~~~python
async def token_handler(token):
   if token == "abcdefg":
      return {
         "uid": "roleaccountthing",
         "roleaccount": True,  # For role accounts, this MUST be set to True, to distinguish from normal user PATs
         "committees": ["httpd", "tomcat",],  # random restriction in this example
         "metadata": {  # the optional metadata dict can be used to manage/log whatever internal information you wish
             "scope": ["scopeA", "scopeB"],  # For instance, you can log which scopes this token can be used within
         },
      }
asfquart.APP.token_handler = token_handler
~~~

This would enable the role account to be granted a session through the bearer auth header:

~~~bash
curl -H "Authorization: bearer abcdefg" https://foo.apache.org/some-endpoint
~~~

## Using scopes for tokens
If the application makes use of scopes to limit what an access token can do, you can note these scopes inside the 
`metadata` dictionary when constructing the session dict to return. The `metadata` dict can be used for whatever 
information you wish to keep about a specific session, and is accessed through `session.metadata` when fetched via 
the usual `session = await asfquart.session.read()` call. Thus, you can test your tokens at the endpoint:

~~~python
REQUIRED_SCOPE = "admin"  # some random scope required for this endpoint

@app.route("/foo")
@asfquart.auth.require  # Require a valid session, can be through a PAT
async def endpoint():
    # Get session
    session = await asfquart.session.read()
    # Ensure it has the right scope, or bail
    if REQUIRED_SCOPE not in session.metadata.get("scope", []):
        raise asfquart.auth.AuthenticationFailed("Your token does not have the required scope for this endpoint")
    # No bail? scope must be proper, do the things..
    do_scoped_stuff()

