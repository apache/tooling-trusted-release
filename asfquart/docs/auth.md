# Authentication, Authorization, and Access

asfquart has built-in decorators for easily handling AAA (Authentication, Authorization, and Access) 
for requests. These decorators have been built with the organizational structure of the ASF in mind, 
and allow you to tailor access to each end-point to suit your specific requirements. These decorators will, 
unless otherwise specified, automatically initiate an OAuth flow if unauthenticated access is attempted.

At present, asfquart features the following auth requirements:

- `asfquart.auth.Requirements.committer`: User must be a committer of any project to access
- `asfquart.auth.Requirements.member`: User must be a member of the Foundation to access
- `asfquart.auth.Requirements.chair`: User must be a chair of one or more projects
- `asfquart.auth.Requirements.mfa_enabled`: User must be logged in using a method that requires multi-factor authentication

These requirements can be passed to the `asfquart.auth.require` decorator to create a list of requirements 
that must pass in order to make use of the endpoint.

By default, requirements are implicitly in the `all_of` category, meaning they are AND'ed together.
You can also OR requirements by using the `any_of` flag instead:

~~~python
@asfquart.auth.require   # Require a valid session of any kind (implicitly, committer)
async def func():
   pass

@asfquart.auth.require({req1, req2})  # Chain two requirements for this endpoint, implicitly AND
async def func():
  pass

@asfquart.auth.require(all_of={req1, req2})  # Same but with explicit AND
@asfquart.auth.require(any_of={req1, req2})  # Same but with explicit OR instead

# You can also use both, such as requiring (req1 AND req2) AND (either req3 OR req4)
@asfquart.auth.require(all_of={req1, req2}, any_of={req3,req4})
~~~

The example below shows how to cordon off specific end-points to certain groups of users:

~~~python
import asfquart
from asfquart.auth import Requirements as R
APP = asfquart.APP
 
# URL that requires some sort of ASF auth (oauth, ldap)
@APP.route("/foo")
@asfquart.auth.require  # Bare decorator means just require a valid session
async def view_that_requires_auth():
   pass
 
# URL that requires 2FA (implies oauth since ldap doesn't have 2fa)
@APP.route("/foo2fa")
@asfquart.auth.require({R.mfa_enabled})
async def view_that_requires_2fa_auth():
   pass
 
# URL that requires a certain org role (2FA implied??)
@APP.route("/foorole")
@asfquart.auth.require({R.member})
async def view_that_requires_member_role():
   pass

# URL that needs at least one of multiple requirements, using the any_of directive
@APP.route("/multirole")
@asfquart.auth.require(any_of={R.member, R.chair})  # Either chair or member (or both) required
async def view_that_requires_some_role():
   pass

~~~
