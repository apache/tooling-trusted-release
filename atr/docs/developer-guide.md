# 2. Developer guide

**Up**: [Apache Trusted Releases documentation](.)
**Prev**: 1. [Introduction to ATR](introduction-to-atr)

This is a guide for developers of ATR, explaining how to make changes to the ATR source code. For more information about how to contribute those changes back to us, please read the [contribution guide](contribution-guide) instead.

## Running the server

To develop ATR locally, we manage dependencies using [uv](https://docs.astral.sh/uv/). To run ATR on ASF hardware, we run it in containers managed by Puppet, but since this guide is about development, we focus on using uv.

### Get the source

[Fork the source code](https://github.com/apache/tooling-trusted-releases/fork) of [ATR on GitHub](https://github.com/apache/tooling-trusted-releases), and then [clone your fork locally](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository).

There are lots of files and directories in the root of the ATR Git repository. The most important thing to know is that `atr/` contains the source code. ATR is a Python application based on [ASFQuart](https://github.com/apache/infrastructure-asfquart), which is based on [Quart](https://github.com/pallets/quart). The Quart web framework is an asynchronous version of [Flask](https://github.com/pallets/flask), a very widely used synchronous web framework. In addition to Python, we use small amounts of JavaScript and TypeScript for the front end.

### Install dependencies

To run ATR locally after cloning the source, you will need to install the following dependencies:

* Any [POSIX](https://en.wikipedia.org/wiki/POSIX) compliant [make](https://frippery.org/make/)
* [mkcert](https://github.com/FiloSottile/mkcert)
* [Python 3.13](https://www.python.org/downloads/release/python-3138/)
* [uv](https://docs.astral.sh/uv/#installation)

You can install Python 3.13 through your package manager or through uv. Here is how to install these dependencies on [Alpine Linux](https://en.wikipedia.org/wiki/Alpine_Linux):

```shell
apk add curl git make mkcert@testing
curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh
uv python install 3.13
```

You do not need to have Alpine Linux to develop ATR. It should work in any POSIX style environment.

### Run the server

Then, to run the server:

```shell
cd tooling-trusted-releases/
mkdir state
make certs-local
make serve-local
```

The `certs-local` step runs `mkcert localhost.apache.org localhost 127.0.0.1 ::1` to generate a locally trusted TLS certificate. If the certificate is not trusted, you may have to follow the [mkcert guide](https://github.com/FiloSottile/mkcert/blob/master/README.md) to resolve the issue.

ATR requires TLS even for development because login is performed through the actual ASF OAuth server. This way, the development behavior aligns closely with the production behavior. We try to minimize differences between development and production environments.

### Load the site

ATR will then be served on various hosts, but we recommend using only `localhost.apache.org`. This requires adding an entry to your `/etc/hosts` and potentially restarting your DNS server. If you do this, the following link should work:

[`https://localhost.apache.org:8080/`](https://localhost.apache.org:8080/)

If you do not want to change your `/etc/hosts`, you can use `127.0.0.1`. You should not use `localhost`. The following link should work:

[`https://127.0.0.1:8080/`](https://127.0.0.1:8080/)

Pick one or the other, because logging into the site on one host does not log you in to the site on any other host.

## Understanding the code

Once you have the server running, you can test it. At this point, it is useful to understand how the ATR works in general. References to symbols in this section are given without their `atr.` prefix, for brevity, and are linked to the respective source code. You should understand e.g. [`server.app`](/ref/atr/server.py:app) to mean `atr.server.app`.

### Hypercorn and ASGI

ATR is an [ASFQuart](https://github.com/apache/infrastructure-asfquart) application, running in [Hypercorn](https://hypercorn.readthedocs.io/en/latest/index.html). The entry point for Hypercorn is [`server.app`](/ref/atr/server.py:app), which is then called with a few standard arguments [as per the ASGI specification](https://asgi.readthedocs.io/en/latest/specs/main.html#overview). We create the `app` object using the following code:

```python
app = create_app(config.get())
```

The [`server.create_app`](/ref/atr/server.py:create_app) function performs a lot of setup, and if you're interested in how the server works then you can read it and the functions it calls to understand the process further. In general, however, when developing ATR we do not make modifications at the ASFQuart, Quart, and Hypercorn levels very often.

### Routes and database

Users request ATR pages over HTTPS, and the ATR server processes those requests in route handlers. Most of those handlers are in [`routes`](/ref/atr/routes/), but not all. What each handler does varies, of course, from handler to handler, but most perform at least one access to the ATR SQLite database.

The path of the SQLite database is configured in [`config.AppConfig.SQLITE_DB_PATH`](/ref/atr/config.py:SQLITE_DB_PATH) by default, and will usually appear as `state/atr.db` with related `shm` and `wal` files. We do not expect ATR to have so many users that we need to scale beyond SQLite.

We use [SQLModel](https://sqlmodel.tiangolo.com/), an ORM utilising [Pydantic](https://docs.pydantic.dev/latest/) and [SQLAlchemy](https://www.sqlalchemy.org/), to create Python models for the ATR database. The core models file is [`models.sql`](/ref/atr/models/sql.py). The most important individual SQLite models in this module are [`Committee`](/ref/atr/models/sql.py:Committee), [`Project`](/ref/atr/models/sql.py:Project), and [`Release`](/ref/atr/models/sql.py:Release).

It is technically possible to interact with SQLite directly, but we do not do that in the ATR source. We use various interfaces in [`db`](/ref/atr/db/__init__.py) for reads, and interfaces in [`storage`](/ref/atr/storage/) for writes. We plan to move the `db` code into `storage` too eventually, because `storage` is designed to have read components and write components. There is also a legacy [`db.interaction`](/ref/atr/db/interaction.py) module which we plan to migrate into `storage`.

These three interfaces, [`routes`](/ref/atr/routes/), [`models.sql`](/ref/atr/models/sql.py), and [`storage`](/ref/atr/storage/), are where the majority of activity happens when developing ATR.

### User interface

ATR provides a web interface for users to interact with the platform, and the implementation of that interface is split across several modules. The web interface uses server-side rendering almost entirely, where HTML is generated on the server and sent to the browser.

The template system in ATR is [Jinja2](https://jinja.palletsprojects.com/), always accessed through the ATR [`template`](/ref/atr/template.py) module. Template files in Jinja2 syntax are stored in [`templates/`](/ref/atr/templates/), and route handlers render them using the asynchronous [`template.render`](/ref/atr/template.py:render) function.

Template rendering can be slow if templates are loaded from disk on every request. To address this, we use [`preload`](/ref/atr/preload.py) to load all templates into memory before the server starts serving requests. The [`preload.setup_template_preloading`](/ref/atr/preload.py:setup_template_preloading) function registers a startup hook that finds and caches every template file.

The ATR user interface includes many HTML forms. We use [WTForms](https://wtforms.readthedocs.io/) for form handling, accessed through the ATR [`forms`](/ref/atr/forms.py) module. The [`forms.Typed`](/ref/atr/forms.py:Typed) base class extends the standard `QuartForm` class in [Quart-WTF](https://quart-wtf.readthedocs.io/). Each form field is created using helper functions such as [`forms.string`](/ref/atr/forms.py:string), [`forms.select`](/ref/atr/forms.py:select), and [`forms.submit`](/ref/atr/forms.py:submit), which handle validation automatically. Forms are rendered in templates, but the ATR `forms` module also provides programmatic rendering through functions that generate HTML styled with Bootstrap.

In addition to templates, we sometimes need to generate HTML programmatically in Python. For this we use [htpy](https://htpy.dev/), another third party library, for building HTML using Python syntax. The ATR [`htm`](/ref/atr/htm.py) module extends htpy with a [`Block`](/ref/atr/htm.py:Block) class that makes it easier to build complex HTML structures incrementally. Using htpy means that we get type checking for our HTML generation, and can compose HTML elements just like any other Python objects. The generated HTML can be embedded in Jinja2 templates or returned directly from route handlers.

### Other important interfaces

The server configuration in [`config`](/ref/atr/config.py) determines a lot of global state, and the [`util`](/ref/atr/util.py) module contains lots of useful code which is used throughout ATR.
