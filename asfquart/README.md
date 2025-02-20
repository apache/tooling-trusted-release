# asfquart - a Quart framework for the ASF
<a href="https://pypi.org/project/asfquart"><img alt="PyPI" src="https://img.shields.io/pypi/v/asfquart.svg?color=blue&maxAge=600" /></a>
<a href="https://pypi.org/project/asfquart"><img alt="PyPI - Python Versions" src="https://img.shields.io/pypi/pyversions/asfquart.svg?maxAge=600" /></a>
<a href="https://github.com/apache/infrastructure-asfquart/actions/workflows/unit-tests.yml?query=branch%3Amain"><img alt="Unit Tests" src="https://github.com/apache/infrastructure-asfquart/actions/workflows/unit-tests.yml/badge.svg?branch=main" /></a>
<a href="https://github.com/apache/infrastructure-asfquart/blob/main/LICENSE"><img alt="Apache License" src="https://img.shields.io/github/license/apache/infrastructure-asfquart" /></a>

This is a [Quart](https://github.com/pallets/quart/) framework for ASF web applications.

On top of Quart, this package layers a lot of functionality, much of which is specific to
the ASF and its infrastructure and preferred approaches for website application development.

asfquart adds the following items to basic quart:

* simple construction of the `APP`
* default `config.yaml`
* watching the .py and config for changes, to cause a restart/reload
* watch SIGINT to halt and SIGUSR2 to restart/reload
* template watching and rendering for EZT templates
* URL path routing for pages and API endpoints
* Oauth with our ASF provider for authn
* LDAP group testing for authz
* long-running tasks and their lifecycle management

Current (known, public) users of asfquart:

* [Board Agenda Tool](https://github.com/apache/infrastructure-agenda/)
* [Infrastructure's Reporting Dashboard](https://github.com/apache/infrastructure-reporting-dashboard)
* [ASF Self Serve Portal](https://github.com/apache/infrastructure-selfserve-portal)


Future users of asfquart:

* Apache STeVe
* Identity management (replaces the old id.a.o)
* Gitbox UI
* ??

## Primer

See the [documentation page](docs/readme.md) for more information.

~~~python
import asfquart
from asfquart.auth import Requirements as R

def my_app():
    # Construct the quart service. By default, the oauth gateway is enabled at /oauth.
    app = asfquart.construct("my_app_service")

    @app.route("/")
    async def homepage():
        return "Hello!"

    @app.route("/secret")
    @asfquart.auth.require(R.committer)
    async def secret_page():
      return "Secret stuff!"
    
    asfquart.APP.run(port=8000)


if __name__ == "__main__":
    my_app()

~~~

## Running unit tests for asfquart

To run manually, use the following commands from the root dir of this repo:

~~~shell
poetry run pytest
~~~
