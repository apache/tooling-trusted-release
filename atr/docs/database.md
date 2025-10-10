# 3.3. Database

**Up**: `3.` [Developer guide](developer-guide)

**Prev**: `3.2.` [Overview of the code](overview-of-the-code)

**Next**: `3.4.` [Build processes](build-processes)

**Sections**:

* [Introduction](#introduction)

## Introduction

ATR stores all of its data in a SQLite database. The database schema is defined in [`models.sql`](/ref/atr/models/sql.py) using [SQLModel](https://sqlmodel.tiangolo.com/), which uses [Pydantic](https://docs.pydantic.dev/latest/) for data validation and [SQLAlchemy](https://www.sqlalchemy.org/) for database operations. This page explains the main features of the database schema to help you understand how data is structured in ATR.
