# 3.4. Storage interface

**Up**: `3.` [Developer guide](developer-guide)

**Prev**: `3.3.` [Database](database)

**Next**: `3.5.` [User interface](user-interface)

**Sections**:

* [Introduction](#introduction)
* [How do we read from storage?](#how-do-we-read-from-storage)
* [How do we write to storage?](#how-do-we-write-to-storage)
* [How do we add new storage functionality?](#how-do-we-add-new-storage-functionality)
* [How do we use outcomes?](#how-do-we-use-outcomes)
* [What about audit logging?](#what-about-audit-logging)

## Introduction

All database writes, and some reads, in ATR go through the [`storage`](/ref/atr/storage/__init__.py) interface. This interface **enforces permissions**, **centralizes audit logging**, and **provides type-safe access** to the database. In other words, avoid calling [`db`](/ref/atr/db/__init__.py) directly in route handlers if possible.

The storage interface recognizes several permission levels: general public (unauthenticated visitors), foundation committer (any ASF account), committee participant (committers and PMC members), committee member (PMC members only), and foundation admin (infrastructure administrators). Each level inherits from the previous one, so for example committee members can do everything committee participants can do, plus additional operations.

The storage interface does not make it impossible to bypass authorization, because you can always import `db` directly and write to the database. But it makes bypassing authorization an explicit choice that requires deliberate action, and it makes the safer path the easier path. This is a pragmatic approach to security: we cannot prevent all mistakes, but we can make it harder to make them accidentally.

## How do we read from storage?

Reading from storage is a work in progress. There are some existing methods, but most of the functionality is currently in `db` or `db.interaction`, and much work is required to migrate this to the storage interface. We have given this less priority because reads are generally safe, with the exception of a few components such as user tokens, which should be given greater migration priority.

## How do we write to storage?

To write to storage we open a write session, request specific permissions, use the exposed functionality, and then handle the outcome. Here is an actual example from [`routes/start.py`](/ref/atr/routes/start.py):

```python
async with storage.write(session.uid) as write:
    wacp = await write.as_project_committee_participant(project_name)
    new_release, _project = await wacp.release.start(project_name, version)
```

The `wacp` object, short for `w`rite `a`s `c`ommittee `p`articipant, provides access to domain-specific writers: `announce`, `checks`, `distributions`, `keys`, `policy`, `project`, `release`, `sbom`, `ssh`, `tokens`, and `vote`.

The write session takes an optional ASF UID, typically `session.uid` from the logged-in user. If you omit the UID, the session determines it automatically from the current request context. The write object checks LDAP memberships and raises [`storage.AccessError`](/ref/atr/storage/__init__.py:AccessError) if the user is not authorized for the requested permission level.

Because projects belong to committees, we provide [`write.as_project_committee_member(project_name)`](/ref/atr/storage/__init__.py:as_project_committee_member) and [`write.as_project_committee_participant(project_name)`](/ref/atr/storage/__init__.py:as_project_committee_participant), which look up the project's committee and authenticate the user as a member or participant of that committee. This is convenient when, for example, the URL provides a project name.

Here is a more complete example from [`blueprints/api/api.py`](/ref/atr/blueprints/api/api.py) that shows the classic three step pattern:

```python
async with storage.write(asf_uid) as write:
    # 1. Request permissions
    wafc = write.as_foundation_committer()

    # 2. Use the exposed functionality
    outcome = await wafc.keys.ensure_stored_one(data.key)

    # 3. Handle the outcome
    key = outcome.result_or_raise()
```

In this case we decide to raise as soon as there is any error. We could also choose to display a warning, ignore the error, collect multiple outcomes for batch processing, or handle it in any other way appropriate for the situation.

## How do we add new storage functionality?

Add methods to classes in the [`storage/writers`](/ref/atr/storage/writers/) or [`storage/readers`](/ref/atr/storage/readers/) directories. Code to perform any action associated with public keys that involves writing to storage, for example, goes in [`storage/writers/keys.py`](/ref/atr/storage/writers/keys.py).

Classes in writer and reader modules must be named to match the permission hierarchy:

```python
class GeneralPublic:
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsGeneralPublic,
        data: db.Session,
    ) -> None:
        self.__write = write
        self.__write_as = write_as
        self.__data = data

class FoundationCommitter(GeneralPublic):
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsFoundationCommitter,
        data: db.Session
    ) -> None:
        super().__init__(write, write_as, data)
        self.__write = write
        self.__write_as = write_as
        self.__data = data

class CommitteeParticipant(FoundationCommitter):
    def __init__(
        self,
        write: storage.Write,
        write_as: storage.WriteAsCommitteeParticipant,
        data: db.Session,
        committee_name: str,
    ) -> None:
        super().__init__(write, write_as, data)
        self.__committee_name = committee_name

class CommitteeMember(CommitteeParticipant):
    ...
```

This hierarchy that this creates is: `GeneralPublic` → `FoundationCommitter` → `CommitteeParticipant` → `CommitteeMember`. You can add methods at any level. A method on `CommitteeMember` is only available to committee members, while a method on `FoundationCommitter` is available to everyone who has logged in.

Use `__private_methods` for helper code that is not part of the public interface. Use `public_methods` for operations that should be available to callers at the appropriate permission level. Consider returning [`Outcome`](/ref/atr/storage/outcome.py:Outcome) types to allow callers flexibility in error handling. Refer to the [section on using outcomes](#how-do-we-use-outcomes) for more details.

After adding a new writer module, register it in the appropriate `WriteAs*` classes in [`storage/__init__.py`](/ref/atr/storage/__init__.py). For example, when adding the `distributions` writer, it was necessary to add `self.distributions = writers.distributions.CommitteeMember(write, self, data, committee_name)` to the [`WriteAsCommitteeMember`](/ref/atr/storage/__init__.py:WriteAsCommitteeMember) class.

## How do we use outcomes?

Consider using **outcome types** from [`storage.outcome`](/ref/atr/storage/outcome.py) when returning results from writer methods. Outcomes let you represent both success and failure without raising exceptions, which gives callers flexibility in how they handle errors.

An [`Outcome[T]`](/ref/atr/storage/outcome.py:Outcome) is either a [`Result[T]`](/ref/atr/storage/outcome.py:Result) wrapping a successful value, or an [`Error[T]`](/ref/atr/storage/outcome.py:Error) wrapping an exception. You can check which it is with the `ok` property or pattern matching, extract the value with `result_or_raise()`, or extract the error with `error_or_raise()`.

Here is an example from [`routes/keys.py`](/ref/atr/routes/keys.py) that processes multiple keys and collects outcomes:

```python
async with storage.write() as write:
    wacm = write.as_committee_member(selected_committee)
    outcomes = await wacm.keys.ensure_associated(keys_text)

success_count = outcomes.result_count
error_count = outcomes.error_count
```

The `ensure_associated` method returns an [`outcome.List`](/ref/atr/storage/outcome.py:List), which is a collection of outcomes. Some keys might import successfully, and others might fail because they are malformed or already exist. The caller can inspect the list to see how many succeeded and how many failed, and present that information to the user.

The `outcome.List` class provides many useful methods: [`results()`](/ref/atr/storage/outcome.py:results) to get only the successful values, [`errors()`](/ref/atr/storage/outcome.py:errors) to get only the exceptions, [`result_count`](/ref/atr/storage/outcome.py:result_count) and [`error_count`](/ref/atr/storage/outcome.py:error_count) to count them, and [`results_or_raise()`](/ref/atr/storage/outcome.py:results_or_raise) to extract all values or raise on the first error.

Use outcomes when an operation might fail for some items but succeed for others, or when you want to give the caller control over error handling. Do not use them when failure should always raise an exception, such as authorization failures or database connection errors. Those should be raised immediately.

## What about audit logging?

Storage write operations can be logged to [`config.AppConfig.STORAGE_AUDIT_LOG_FILE`](/ref/atr/config.py:STORAGE_AUDIT_LOG_FILE), which is `state/storage-audit.log` by default. Each log entry is a JSON object containing the timestamp, the action name, and relevant parameters. When you write a storage method that should be audited, call `self.__write_as.append_to_audit_log(**kwargs)` with whatever parameters are relevant to that specific operation. The action name is extracted automatically from the call stack using [`log.caller_name()`](/ref/atr/log.py:caller_name), so if the method is called [`i_am_a_teapot`](https://datatracker.ietf.org/doc/html/rfc2324), the audit log will show `i_am_a_teapot` without you having to pass the name explicitly.

Audit logging must be done manually because the values to log are often those computed during method execution, not just those passed as arguments which could be logged automatically. When deleting a release, for example, we log `asf_uid` (instance attribute), `project_name` (argument), and `version` (argument), but when issuing a JWT from a PAT, we log `asf_uid` (instance attribute) and `pat_hash` (_computed_). Each operation logs what makes sense for that operation.
