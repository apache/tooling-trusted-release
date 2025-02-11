# asfquart - a Quart framework for the ASF
![Unit Tests](https://github.com/apache/infrastructure-asfquart/actions/workflows/unit-tests.yml/badge.svg)
  
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

Current users of asfquart:

* Board Agenda tool
* Infrastructure's Reporting Dashboard
* personal/home project of gstein
* ??

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
