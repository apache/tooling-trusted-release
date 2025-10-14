# 3.8. Code conventions

**Up**: `3.` [Developer guide](developer-guide)

**Prev**: `3.7.` [Running and creating tests](running-and-creating-tests)

**Next**: `3.9.` [How to contribute](how-to-contribute)

**Sections**:

* [Python code](#python-code)
* [HTML](#html)
* [Markdown](#markdown)

## Python code

### Follow PEP 8 rules by default

Follow [PEP 8](https://peps.python.org/pep-0008/) unless otherwise indicated in this document. Some of the conventions listed below recapitulate or add exceptions to PEP 8 rules.

Obey all project local lints, e.g. the use of `ruff` and specific `ruff` rules.

### Keep the primary execution path to the left

Structure code so that the most likely, normal, successful execution path remains at the level of least indentation. Handle error cases and edge conditions early with guard clauses, and then continue with the main logic. This makes it easier to identify the primary execution flow.

```python
# Avoid
def process_data(data):
    if data is not None:
        if len(data) > 0:
            if validate(data):
                return transform(data)
            else:
                raise ValueError("Invalid data")
        else:
            raise ValueError("Empty data")
    else:
        raise ValueError("No data")

# Prefer
def process_data(data):
    if data is None:
        raise ValueError("No data")
    if len(data) == 0:
        raise ValueError("Empty data")
    if not validate(data):
        raise ValueError("Invalid data")

    return transform(data)
```

### Avoid excessive indentation

When you find yourself nesting code more than two or three levels deep, extract the nested logic into separate functions. This improves readability, testability, and maintainability. Each function should handle a single, well defined piece of logic.

### Do not use lint or type checker ignore statements

You must not use `# noqa`, `# type: ignore`, or equivalents, even to ignore specific errors. The single exception to this is when there is a bug in the linter or type checker.

File level lint ignores can be added to the project's `pyproject.toml`, but they must be used sparingly.

### Use double quotes for all strings

This includes triple quoted strings.

### Prefix private interfaces with a single underscore

Prefix all private interfaces, e.g. functions, classes, constants, variables, with a single underscore. An interface is private when used exclusively within its containing module and not referenced by external code, templates, or processes.

Exceptions to this rule include:

- Type variables
- Enumerations
- Methods requiring interface compatibility with their superclass
- Nested functions (which should generally be avoided)

Scripts are explicitly _not_ an exception. Underscores should be used to prefix private interfaces in scripts for consistency, e.g. so that linters don't need to carry exceptions, and to ease potential migration to modules.

### Avoid nested functions

All function definitions should be at the top level. This is not a hard rule, but should only be broken when absolutely necessary.

### Use UPPERCASE for top level constants

Define top level constants using `UPPERCASE` letters. Don't forget to apply an underscore prefix to constants which are private to their module.

Do not use uppercase for constants within functions and methods.

### Use the `Final` type with all constants

This pattern must be followed for top level constants, and should be followed for function and method level constants too. The longer the function, the more important the use of `Final`.

### Prefix global variables with `global_`

Top level variables should be avoided. When their use is necessary, prefix them with `global_`, using lowercase letters, to ensure clear identification of their scope. Use an underscore prefix too, `_global_`, when the variable is private.

### Import modules as their least significant name part

Import modules using their least significant name component:

```python
# Prefer
import a.b.c as c

# Avoid
import a.b.c
```

This convention aligns with Go's package naming practices. Follow [Go naming rules](https://go.dev/blog/package-names) for all modules.

This only applies to modules outside of the Python standard library. The standard library module `os.path`, for example, must always be imported using the form `import os.path`, and _not_ `import os.path as path`.

Furthermore, if a third party module to be imported would conflict with a Python standard library module, then that third party module must be imported with one extra level.

```python
# Prefer
import asyncio.subprocess
import sqlalchemy.ext as ext
import aiofiles.os

# Avoid
import asyncio.subprocess as subprocess
import sqlalchemy.ext.asyncio as asyncio
import aiofiles.os.path as path
```

It's possible to use `from a.b import c` instead of `import a.b.c as c` when `c` is a module, but we prefer the latter form because it makes it clear that `c` must be a module, whereas in the former `from a.b import c` form, `c` could be any interface.

TODO: There's a question as to whether we could actually use `import aiofiles.os.path as path` since we import `os.path` as `os.path` and not `path`.

TODO: Sometimes we're using `as` for standard library modules. We should decide what to do about this.

### Avoid duplicated module names

Try to avoid using, for example, `baking/apple/pie.py` and `baking/cherry/pie.py` because these will both be imported as `pie` and one will have to be renamed.

If there are duplicates imported within a single file, they should be disambiguated by the next level up. In the pie example, that would be `import baking.apple as apple` and then `apple.pie`, and `import baking.cherry as cherry` and `cherry.pie`.

### Never import names directly from modules

Avoid importing specific names from modules:

```python
# Prefer
import p.q.r as r
r.s()

# Avoid
from p.q.r import s
s()
```

The `collections.abc`, `types`, and `typing` modules are an exception to this rule. Always import `collections.abc`, `types` and `typing` interfaces directly using the `from` syntax:

```python
# Prefer
from typing import Final

CONSTANT: Final = "CONSTANT"

# Avoid
import typing

CONSTANT: typing.Final = "CONSTANT"
```

### Use concise typing patterns

Do not use `List` or `Optional` etc. from the typing module.

```python
# Prefer
def example() -> list[str | None]:
    return ["a", "c", None]

# Avoid
from typing import List, Optional

def example() -> List[Optional[str]]:
    return ["a", "c", None]
```

### Never name interfaces after their module

Do not name interfaces with the same identifier as their containing module. For example, in a module named `example`, the function names `example` and `example_function` are prohibited.

### Keep modules small and focused

Maintain modules with a reasonable number of interfaces. Though no strict limits are enforced, modules containing numerous classes, constants, or functions should be considered for logical subdivision. Exceptions may be made when closely related functionality necessitates grouping multiple interfaces within a single module.

### Name functions to group related items together alphabetically

Modules should, in general, be split into small collections of code items. If this is unavoidable, large groups of functions should be named hierarchically, with the most general category first, followed by increasingly specific details. This makes related functions group together naturally when sorted alphabetically, making code navigation and discovery easier.

**Example**:

Instead of scattered, hard to find related functions:

```python
# Avoid
def get_user_from_db():
def insert_new_record():
def query_user_settings():
def update_db_record():
```

Use hierarchical naming that groups related functionality:

```python
# Prefer
def db_user_get():
def db_record_insert():
def db_user_settings_query():
def db_record_update():
```

Note that if the same prefix is used for a large number of functions, that indicates that these functions are a good candidate for splitting off into their own module.

**Example**:

Another example with license files, the wrong way:

```python
# Avoid
def check_root_license_file():      # Lost amongst other "check_" functions
def validate_package_license():     # Separated from other license functions
def verify_license_files():         # Yet another scattered license function
```

The right way:

```python
# Prefer
def license_root_file_check():      # All license related functions
def license_package_validate():     # will appear together when
def license_files_verify():         # sorted alphabetically
```

Note how verbs tend to come last, so that function names now read in an object oriented style, like a module, object, and action.

While this approach can lead to slightly longer function names, the benefits of improved code organisation and discoverability outweigh the verbosity.

Classes should always be placed before functions. Private, underscored, classes should be placed after all public classes, and likewise for functions.

### Use numbers in function names with long, linear flow

In some cases, such as testing, computation proceeds through a predictable, linear path and is implemented across many functions. In such cases, use numbers in the function names to make the order clear. One disadvantage to this style is the requirement to renumber all subsequent functions when inserting a new function in the middle.

**Example:**

```python
def example_01_start():
def example_02_prepare():
def example_03_query():
def example_04_filter():
def example_05_process():
def example_06_clean_up():
```

### Give helper functions the same prefix as their parent function

This makes it easier to find all the functions related to a specific task.

**Example**:

Instead of:

```python
# Avoid
def _verify_archive_integrity():
def _do_something_in_verify_archive_integrity():
```

Use the same prefix:

```python
# Prefer
def _verify_archive_integrity():
def _verify_archive_integrity_do_something():
```

This makes it easier to find all the functions related to a specific task, and means that they sort together.

### Keep cyclomatic complexity below 10

We limit function complexity to a score of 10. If the linter complains, your function is doing too much.

Cyclomatic complexity counts the number of independent paths through code: more if and else branches, loops, and exception handlers means higher complexity. Complex code is harder to test, maintain, and understand. The easiest way to fix high complexity is usually to refactor a chunk of related logic into a separate helper function.

### Replace synchronous calls with asynchronous counterparts in async code

Our use of blockbuster enables automatic detection of synchronous function calls within asynchronous code. When detected, replace these calls with their asynchronous equivalents without performance testing. The conversion process typically requires minimal, trivial effort.

Exceptions to this rule apply only in these scenarios:

- When dealing with third party dependencies
- When the asynchronous equivalent function is unknown

If either exception applies, either submit a brief issue with the blockbuster traceback, notify the team via Slack, or add a code comment if part of another commit. An ATR Tooling engineer will address the issue without requiring significant time investment from you.

### Always use parentheses to group complex nested subexpressions

Complex subexpressions are those which contain a keyword or operator.

```python
# Avoid
a or b and c == d or not e or f

# Prefer
(a or b) and (c == d) or (not e) or f
```

Because `f` is not a complex expression, it does not get parenthesised. Also because this rule is about subexpressions only, we do not put parethenses around the top level.

```python
# Avoid
if (a or b):
    ...

# Prefer
if a or b:
    ...
```

### Use terse comments on their own lines

Place comments on dedicated lines preceding the relevant code block. Comments at the ends of lines are strictly reserved for linter or type checker directives. This convention enhances code scannability for such directives. General comments must not appear at the end of code lines. Keep comments concise, using sentence case without terminal punctuation. Each sentence forming a comment must occupy its own line.


### Prefer explicit checks over `assert`

We do not use `assert`. If you need to guard against invalid states or inputs, use standard `if` checks and raise appropriate exceptions. If you need to help type checkers understand the type of a variable within a specific code block, in other words if you need to narrow a type, then use `if isinstance(...)` or `if not isinstance(...)` as appropriate.

### Never use `case _` when pattern matching exhausive types

Using `case _` breaks type checking in such situations.

## HTML

### Use sentence case for headings, form labels, and submission buttons

We write headings, form labels, and submission buttons in the form "This is some text", and not "This is Some Text" or "This Is Some Text". This follows the [Wikipedia style for headings](https://en.wikipedia.org/wiki/Wikipedia:Manual_of_Style#Section_headings).

### Use Bootstrap classes for all style

We use Bootstrap classes for style, and avoid custom classes unless absolutely necessary. If you think that you have to resort to a custom class, consult the list of [Bootstrap classes](https://bootstrapclasses.com/) for guidance. There is usually a class for what you want to achieve, and if there isn't then you may be making things too complicated. Complicated, custom style is difficult for a team to maintain. If you still believe that a new class is strictly warranted, then the class must be prefixed with a project label, e.g. `example-` if the project is called `example`. Classes can go in `<style>` elements in `stylesheet` template blocks in such cases. The use of the `style` attribute on any HTML element is forbidden.

## Markdown

### Use `_` for emphasis and `**` for strong emphasis

Do not use `*` for emphasis or `__` for strong emphasis.
