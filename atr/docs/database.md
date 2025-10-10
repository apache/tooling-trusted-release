# 3.3. Database

**Up**: `3.` [Developer guide](developer-guide)

**Prev**: `3.2.` [Overview of the code](overview-of-the-code)

**Next**: `3.4.` [Build processes](build-processes)

**Sections**:

* [Introduction](#introduction)
* [Core models](#core-models)
* [Other features](#other-features)

## Introduction

ATR stores all of its data in a SQLite database. The database schema is defined in [`models.sql`](/ref/atr/models/sql.py) using [SQLModel](https://sqlmodel.tiangolo.com/), which uses [Pydantic](https://docs.pydantic.dev/latest/) for data validation and [SQLAlchemy](https://www.sqlalchemy.org/) for database operations. This page explains the main features of the database schema to help you understand how data is structured in ATR.

## Core models

The three most important models in ATR are [`Committee`](/ref/atr/models/sql.py:Committee), [`Project`](/ref/atr/models/sql.py:Project), and [`Release`](/ref/atr/models/sql.py:Release).

A [`Committee`](/ref/atr/models/sql.py:Committee) represents a PMC or PPMC at the ASF. Each committee has a name, which is the primary key, and a full name for display purposes. Committees can have child committees, which is used for the relationship between the Incubator PMC and individual podling PPMCs. Committees also have lists of committee members and committers stored as JSON arrays.

A [`Project`](/ref/atr/models/sql.py:Project) belongs to a committee and can have multiple releases. Projects have a name as the primary key, along with metadata such as a description and category and programming language tags. Each project can optionally have a [`ReleasePolicy`](/ref/atr/models/sql.py:ReleasePolicy) that defines how releases should be handled, including e.g. vote templates and GitHub workflow configuration.

A [`Release`](/ref/atr/models/sql.py:Release) belongs to a project and represents a specific version of software which is voted on by a committee. The primary key is a name derived from the project name and version. Releases have a phase that indicates their current state in the release process, from draft composition to final publication. Each release can have multiple [`Revision`](/ref/atr/models/sql.py:Revision) instances before final publication, representing iterations of the underlying files.

## Other features

The models themselves are the most important components, but to support those models we need other components such as enumerations, column types, automatically populated fields, computed properties, and constraints.

### Enumerations

ATR uses Python enumerations to ensure that certain fields only contain valid values. The most important enumeration is [`ReleasePhase`](/ref/atr/models/sql.py:ReleasePhase), which defines the four phases of a release: `RELEASE_CANDIDATE_DRAFT` for composing, `RELEASE_CANDIDATE` for voting, `RELEASE_PREVIEW` for finishing, and `RELEASE` for completed releases.

The [`TaskStatus`](/ref/atr/models/sql.py:TaskStatus) enumeration defines the states a task can be in: `QUEUED`, `ACTIVE`, `COMPLETED`, or `FAILED`. The [`TaskType`](/ref/atr/models/sql.py:TaskType) enumeration lists all the different types of background tasks that ATR can execute, from signature checks to SBOM generation.

The [`DistributionPlatform`](/ref/atr/models/sql.py:DistributionPlatform) enumeration is more complex, as each value contains not just a name but a [`DistributionPlatformValue`](/ref/atr/models/sql.py:DistributionPlatformValue) with template URLs and configuration for different package distribution platforms like PyPI, npm, and Maven Central.

### Special column types

SQLite does not support all the data types we need, so we use SQLAlchemy type decorators to handle conversions. The [`UTCDateTime`](/ref/atr/models/sql.py:UTCDateTime) type ensures that all datetime values are stored in UTC and returned as timezone-aware datetime objects. When Python code provides a datetime with timezone information, the type decorator converts it to UTC before storing. When reading from the database, it adds back the UTC timezone information.

The [`ResultsJSON`](/ref/atr/models/sql.py:ResultsJSON) type handles storing task results. It automatically serializes Pydantic models to JSON when writing to the database, and deserializes them back to the appropriate result model when reading.

### Automatic field population

Some fields are populated automatically using SQLAlchemy event listeners. When a new [`Revision`](/ref/atr/models/sql.py:Revision) is created, the [`populate_revision_sequence_and_name`](/ref/atr/models/sql.py:populate_revision_sequence_and_name) function runs before the database insert. This function queries for the highest existing sequence number for the release, increments it, and sets both the `seq` and `number` fields. It also constructs the revision name by combining the release name with the revision number.

The [`check_release_name`](/ref/atr/models/sql.py:check_release_name) function runs before inserting a release. If the release name is empty, it automatically generates it from the project name and version using the [`release_name`](/ref/atr/models/sql.py:release_name) helper function.

### Computed properties

Some properties are computed dynamically rather than stored in the database. The `Release.latest_revision_number` property is implemented as a SQLAlchemy column property using a correlated subquery. This means that when you access `release.latest_revision_number`, SQLAlchemy automatically executes a query to find the highest revision number for that release. The query is defined once in [`RELEASE_LATEST_REVISION_NUMBER`](/ref/atr/models/sql.py:RELEASE_LATEST_REVISION_NUMBER) and attached to the `Release` class.

Projects have many computed properties that provide access to release policy settings with appropriate defaults. For example, `Project.policy_start_vote_template` returns the custom vote template if one is configured, or falls back to `Project.policy_start_vote_default` if not. This pattern allows projects to customize their release process while providing sensible defaults.

### Constraints and validation

Database constraints ensure data integrity. The [`Task`](/ref/atr/models/sql.py:Task) model includes a check constraint that validates the status transitions. A task must start in `QUEUED` state, can only transition to `ACTIVE` when `started` and `pid` are set, and can only reach `COMPLETED` or `FAILED` when the `completed` timestamp is set. These constraints prevent invalid state transitions at the database level.

Unique constraints ensure that certain combinations of fields are unique. The `Release` model has a unique constraint on `(project_name, version)` to prevent creating duplicate releases for the same project version. The `Revision` model has two unique constraints: one on `(release_name, seq)` and another on `(release_name, number)`, ensuring that revision numbers are unique within a release.
