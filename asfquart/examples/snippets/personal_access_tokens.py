#!/usr/bin/env python3
""" Example handler for personal access tokens (PATs) in asfquart """
import os
import yaml
import easydict
import asyncio
import asfquart


ROLE_ACCOUNT_CONFIG = "roleaccounts.yaml"  # See roleaccounts.yaml in this example dir

def load_accounts():
  if os.path.isfile(ROLE_ACCOUNT_CONFIG):
    yml = easydict.EasyDict(yaml.safe_load(open(ROLE_ACCOUNT_CONFIG)))
  else:
    print(f"Could not find role account config file {ROLE_ACCOUNT_CONFIG}, no role accounts set up")
    yml = {}

async def token_handler(token):
  # Iterate through all role accounts
  for rolename, roledata in yml.items():
    # If token matches, return the session dict.
    # SHOULD have: uid, email, fullname, roleaccount
    if roledata.token == token:
      session = {
        "uid": rolename,
        "email": "root@apache.org",
        "fullname": roledata.name,
        "roleaccount": True,
        "metadata": {
          "scope": roledata.scope,  # Mark the scope of this roleaccount (or PAT) internally
        }
      }
      return session

def my_app():
    app = asfquart.construct("my_simple_app")
    app.token_handler = token_handler  # Set the PAT handler

    # Default homepage
    @app.route("/")
    async def homepage():
        return "Hello!"

    # Add a secret roleaccount-only URI for testing
    @app.route("/secret")
    @asfquart.auth.require(asfquart.auth.Requirements.roleaccount)
    async def secret_roleaccount_page():
        return await asfquart.session.read()

    app.run(port=8000)
  

if __name__ == "__main__":
    my_app()
