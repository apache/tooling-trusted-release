# OAuth workflows

asfquart will, by default, set up an OAuth endpoint at `/auth`. Unauthenticated access 
to any restricted end-point will automatically trigger a redirect to the OAuth workflow 
and redirect back to the restricted end-point once successful. 

You can tailor these automatic behavior to suit your need, as shown in this example:

~~~python
import asfquart

# Construct an app, with auto OAuth at /my_oauth
app = asfquart.construct("myapp", oauth="/my_oauth")

# Make another app, but do not enable oauth nor force login redirect (implied by no oauth)
otherapp = asfquart.construct("otherapp", oauth=None)

# Make a third app, enable oauth at /auth, but do not force logins
thirdapp = asfquart.construct("thirdapp", oauth="/auth", force_login=False)
~~~

