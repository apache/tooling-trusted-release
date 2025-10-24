# 3.6. Tasks

**Up**: `3.` [Developer guide](developer-guide)

**Prev**: `3.5.` [User interface](user-interface)

**Next**: `3.7.` [Build processes](build-processes)

**Sections**:

* [Introduction](#introduction)
* [Checks](#checks)

## Introduction

Tasks are computations run in the background in dedicated worker processes orchestrated by a manager.

## Checks

One important subset of task in ATR is the check. Checks are run when a release manager adds or modifies files in a release candidate draft. The outputs of the checks alert the release manager to potential issues.

There are several checks for correctness that are already built out, and this how-to provides pointers for developers wishing to add new checks for relevant pieces of a release. Currently as of `alpha-2` ATR has checks for the following:

1. Correct hashing
1. Compliant license
1. File paths
1. RAT results
1. Correct signature
1. Well-formed tarballs
1. Well-formed zip files

### Adding a task check module

In `atr/tasks/checks` you will find several modules that perform these check tasks, including `hashing.py`, `license.py`, etc. To write a new check task, add a module here that performs the checks needed.

### Importing and using a check module

In `atr/tasks/__init__.py` you will see imports for existing modules where you can add an import for new check task, for example:

```python
import atr.tasks.checks.hashing as hashing
import atr.tasks.checks.license as license
```

And in the `resolve` function you will see where those modules are exercised where you can add a `case` statement for the new task:

```python
def resolve(task_type: sql.TaskType) -> Callable[..., Awaitable[results.Results | None]]:  # noqa: C901
    match task_type:
        case sql.TaskType.HASHING_CHECK:
            return hashing.check
        case sql.TaskType.KEYS_IMPORT_FILE:
            return keys.import_file
        case sql.TaskType.LICENSE_FILES:
            return license.files
        case sql.TaskType.LICENSE_HEADERS:
            return license.headers
```

### Defining a task type

In `atr/models/sql.py` you will find the `TaskType` class where you can add a new mapping for the task:

```python
class TaskType(str, enum.Enum):
    HASHING_CHECK = "hashing_check"
    KEYS_IMPORT_FILE = "keys_import_file"
    LICENSE_FILES = "license_files"
    LICENSE_HEADERS = "license_headers"
```
