# 3.2. Overview of the code

**Up**: `3.` [Developer guide](developer-guide)

**Prev**: `3.1.` [Running the server](running-the-server)

**Next**: `3.3.` [Database](database)

**Sections**:

* [Introduction](#introduction)
* [Hypercorn and ASGI](#hypercorn-and-asgi)
* [Routes and database](#routes-and-database)
* [User interface](#user-interface)
* [Scheduling and tasks](#scheduling-and-tasks)
* [API](#api)
* [Other important interfaces](#other-important-interfaces)

## Introduction

This page is a high level view of the ATR code. References to symbols in this section are given without their `atr.` prefix, for brevity, and are linked to the respective source code. You should understand e.g. [`server.app`](/ref/atr/server.py:app) to mean `atr.server.app`.

## Hypercorn and ASGI

ATR is an [ASFQuart](https://github.com/apache/infrastructure-asfquart) application, running in [Hypercorn](https://hypercorn.readthedocs.io/en/latest/index.html). The entry point for Hypercorn is [`server.app`](/ref/atr/server.py:app), which is then called with a few standard arguments [as per the ASGI specification](https://asgi.readthedocs.io/en/latest/specs/main.html#overview). We create the `app` object using the following code:

```python
app = create_app(config.get())
```

The [`server.create_app`](/ref/atr/server.py:create_app) function performs a lot of setup, and if you're interested in how the server works then you can read it and the functions it calls to understand the process further. In general, however, when developing ATR we do not make modifications at the ASFQuart, Quart, and Hypercorn levels very often.

## Routes and database

Users request ATR pages over HTTPS, and the ATR server processes those requests in route handlers. Most of those handlers are in [`routes`](/ref/atr/routes/), but not all. What each handler does varies, of course, from handler to handler, but most perform at least one access to the ATR SQLite database.

The path of the SQLite database is configured in [`config.AppConfig.SQLITE_DB_PATH`](/ref/atr/config.py:SQLITE_DB_PATH) by default, and will usually appear as `state/atr.db` with related `shm` and `wal` files. We do not expect ATR to have so many users that we need to scale beyond SQLite.

We use [SQLModel](https://sqlmodel.tiangolo.com/), an ORM utilising [Pydantic](https://docs.pydantic.dev/latest/) and [SQLAlchemy](https://www.sqlalchemy.org/), to create Python models for the ATR database. The core models file is [`models.sql`](/ref/atr/models/sql.py). The most important individual SQLite models in this module are [`Committee`](/ref/atr/models/sql.py:Committee), [`Project`](/ref/atr/models/sql.py:Project), and [`Release`](/ref/atr/models/sql.py:Release).

It is technically possible to interact with SQLite directly, but we do not do that in the ATR source. We use various interfaces in [`db`](/ref/atr/db/__init__.py) for reads, and interfaces in [`storage`](/ref/atr/storage/) for writes. We plan to move the `db` code into `storage` too eventually, because `storage` is designed to have read components and write components. There is also a legacy [`db.interaction`](/ref/atr/db/interaction.py) module which we plan to migrate into `storage`.

These three interfaces, [`routes`](/ref/atr/routes/), [`models.sql`](/ref/atr/models/sql.py), and [`storage`](/ref/atr/storage/), are where the majority of activity happens when developing ATR.

## User interface

ATR provides a web interface for users to interact with the platform, and the implementation of that interface is split across several modules. The web interface uses server-side rendering almost entirely, where HTML is generated on the server and sent to the browser.

The template system in ATR is [Jinja2](https://jinja.palletsprojects.com/), always accessed through the ATR [`template`](/ref/atr/template.py) module. Template files in Jinja2 syntax are stored in [`templates/`](/ref/atr/templates/), and route handlers render them using the asynchronous [`template.render`](/ref/atr/template.py:render) function.

Template rendering can be slow if templates are loaded from disk on every request. To address this, we use [`preload`](/ref/atr/preload.py) to load all templates into memory before the server starts serving requests. The [`preload.setup_template_preloading`](/ref/atr/preload.py:setup_template_preloading) function registers a startup hook that finds and caches every template file.

The ATR user interface includes many HTML forms. We use [WTForms](https://wtforms.readthedocs.io/) for form handling, accessed through the ATR [`forms`](/ref/atr/forms.py) module. The [`forms.Typed`](/ref/atr/forms.py:Typed) base class extends the standard `QuartForm` class in [Quart-WTF](https://quart-wtf.readthedocs.io/). Each form field is created using helper functions such as [`forms.string`](/ref/atr/forms.py:string), [`forms.select`](/ref/atr/forms.py:select), and [`forms.submit`](/ref/atr/forms.py:submit), which handle validation automatically. Forms are rendered in templates, but the ATR `forms` module also provides programmatic rendering through functions that generate HTML styled with Bootstrap.

In addition to templates, we sometimes need to generate HTML programmatically in Python. For this we use [htpy](https://htpy.dev/), another third party library, for building HTML using Python syntax. The ATR [`htm`](/ref/atr/htm.py) module extends htpy with a [`Block`](/ref/atr/htm.py:Block) class that makes it easier to build complex HTML structures incrementally. Using htpy means that we get type checking for our HTML generation, and can compose HTML elements just like any other Python objects. The generated HTML can be embedded in Jinja2 templates or returned directly from route handlers.

## Scheduling and tasks

Many operations in ATR are too slow to run during an HTTP request, so we run them asynchronously in background worker processes. The task scheduling system in ATR is built from three components: a task queue stored in the SQLite database, a worker manager that spawns and monitors worker processes, and the worker processes themselves that claim and execute tasks.

The task queue is stored in a table defined by the [`Task`](/ref/atr/models/sql.py:Task) model in [`models.sql`](/ref/atr/models/sql.py). Each task has a status, a type, arguments encoded as JSON, and metadata such as when it was added and which user created it. When route handlers need to perform slow operations, they create a new `Task` row with status `QUEUED` and commit it to the database.

The ATR [`manager`](/ref/atr/manager.py) module provides the [`WorkerManager`](/ref/atr/manager.py:WorkerManager) class, which maintains a pool of worker processes. When the ATR server starts, the manager spawns a configurable number of worker processes and monitors them continuously. The manager checks every few seconds whether workers are still running, whether any tasks have exceeded their time limits, and whether the worker pool needs to be replenished. If a worker process exits after completing its tasks, the manager spawns a new one automatically. If a task runs for too long, the manager terminates it and marks the task as failed. Worker processes are represented by [`WorkerProcess`](/ref/atr/manager.py:WorkerProcess) objects.

The ATR [`worker`](/ref/atr/worker.py) module implements the workers. Each worker process runs in a loop. It claims the oldest queued task from the database, executes it, records the result, and then claims the next task atomically using an `UPDATE ... WHERE` statement. After a worker has processed a fixed number of tasks, it exits voluntarily to help to avoid memory leaks. The manager then spawns a fresh worker to replace it. Task execution happens in the [`_task_process`](/ref/atr/worker.py:_task_process) function, which resolves the task type to a handler function and calls it with the appropriate arguments.

Tasks themselves are defined in the ATR [`tasks`](/ref/atr/tasks/) directory. The [`tasks`](/ref/atr/tasks/__init__.py) module contains functions for queueing tasks and resolving task types to their handler functions. Task types include operations such as importing keys, generating SBOMs, sending messages, and importing files from SVN. The most common category of task is automated checks on release artifacts. These checks are implemented in [`tasks/checks/`](/ref/atr/tasks/checks/), and include verifying file hashes, checking digital signatures, validating licenses, running Apache RAT, and checking archive integrity.

## API

The ATR API provides programmatic access to most ATR functionality. API endpoints are defined in [`blueprints.api.api`](/ref/atr/blueprints/api/api.py), and their URL paths are prefixed with `/api/`. The API uses [OpenAPI](https://www.openapis.org/) for documentation, which is automatically generated from the endpoint definitions and served at `/api/docs`. Users send requests with a [JWT](https://en.wikipedia.org/wiki/JSON_Web_Token) created from a [PAT](https://en.wikipedia.org/wiki/Personal_access_token). The [`jwtoken`](/ref/atr/jwtoken.py) module handles issuing and verifying these tokens. API endpoints that require authentication use the [`@jwtoken.require`](/ref/atr/jwtoken.py:require) decorator, which automatically extracts and verifies the JWT.

API request and response models are defined in [`models.api`](/ref/atr/models/api.py) using Pydantic. Each endpoint has an associated request model that validates incoming data, and a response model that validates outgoing data. The API returns JSON in all cases, with appropriate HTTP status codes.

## Other important interfaces

ATR uses ASF OAuth for user login, and then determines what actions each user can perform based on their committee memberships. The ATR [`principal`](/ref/atr/principal.py) module handles authorization by checking whether users are members of relevant committees. It queries and caches LDAP to get committee membership information. The [`Authorisation`](/ref/atr/principal.py:Authorisation) class provides methods to check whether a user is a member of a committee or a project participant, which can result in different levels of access.

The server configuration in [`config`](/ref/atr/config.py) determines a lot of global state, and the [`util`](/ref/atr/util.py) module contains lots of useful code which is used throughout ATR.
