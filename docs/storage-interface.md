# Storage interface

All writes to the database and filesystem are to be mediated through the storage interface in `atr.storage`. The storage interface **enforces permissions**, **centralises audit logging**, and **exposes misuse resistant methods**.

## How do we use the storage interface?

Open a storage interface session with a context manager. Then:

1. Request permissions from the session depending on the role of the user.
2. Use the exposed functionality.
3. Handle the outcome or outcomes.

Here is an actual example from our API code:

```python
async with storage.write(asf_uid) as write:
    wafc = write.as_foundation_committer()
    ocr: types.Outcome[types.Key] = await wafc.keys.ensure_stored_one(data.key)
    key = ocr.result_or_raise()

    for selected_committee_name in selected_committee_names:
        wacm = write.as_committee_member(selected_committee_name)
        outcome: types.Outcome[types.LinkedCommittee] = await wacm.keys.associate_fingerprint(
            key.key_model.fingerprint
        )
        outcome.result_or_raise()
```

The `wafm` (**w**rite **a**s **f**oundation **m**ember) object exposes functionality which is only available to foundation members. The `wafm.keys.ensure_stored_one` method is an example of such functionality. The `wacm` object goes further and exposes functionality only available to committee members.

In this case we decide to raise as soon as there is any error. We could also choose instead to display a warning, ignore the error, etc.

The first few lines in the context session show the classic three step approach. Here they are again with comments:

```python
    # 1. Request permissions
    wafc = write.as_foundation_committer()

    # 2. Use the exposed functionality
    ocr: types.Outcome[types.Key] = await wafc.keys.ensure_stored_one(data.key)

    # 3. Handle the outcome
    key = ocr.result_or_raise()
```

## How do we add functionality to the storage interface?

Add all the functionality to classes in modules in the `atr/storage/writers` directory. Code to write public keys to storage, for example, goes in `atr/storage/writers/keys.py`.

Classes in modules in the `atr/storage/writers` directory must be named as follows:

```python
class GeneralPublic:
    ...

class FoundationCommitter(GeneralPublic):
    ...

class CommitteeParticipant(FoundationCommitter):
    ...

class CommitteeMember(CommitteeParticipant):
    ...
```

This creates a hierarchy, `GeneralPublic` → `FoundationCommitter` → `CommitteeParticipant` → `CommitteeMember`. We can add other permissions levels if necessary.

Use `__private_methods` for code specific to one permission level which is not exposed in the interface, e.g. helpers. Use `public_methods` for code appropriate to expose when users meet the appropriate permission level. Consider returning outcomes, as explained in the next section.

## Returning outcomes

Consider using the **outcome types** in `atr.storage.types` when returning results from writer module methods. The outcome types _solve many problems_, but here is an example:

Imagine the user is submitting a `KEYS` file containing several keys. Some of the keys are already in the database, some are not in the database, and some are broken keys that do not parse. After processing, each key is associated with a different state: the key was parsed but not added, the key was parsed and added, or the key wasn't even parsed. We consider some of these success states, some warning states, and others error states.

How do we represent this?

Outcomes are one possibility. For each key we can return `OutcomeResult` for a success, and `OutcomeException` when there was a Python error. The caller can then decide what to do with this information. It might ignore the exception, raise it, or print an error message to the user. Better yet, we can aggregate these into an `Outcomes` list, which provides many useful methods for processing all of the outcomes together. It can count how many exceptions there were, for example, or apply a function to all results only, leaving the exceptions alone.

We do not have to return outcomes from public storage interface methods, but these classes were designed to make the storage interface easy to use.

### Outcome design patterns

One common pattern when designing outcome types is about how to handle an **exception after a success**, and how to handle a **warning during success**:

* An **exception after a success** is when an object is processed in multiple stages, and the first few stages succeed but then subsequently there is an exception.
* A **warning during success** is when an object is processed in multiple stages, an exception is raised, but we determine that we can proceed to subsequent stages as long as we keep a note of the exception.

Both of these workflows appear incompatible with outcomes. In outcomes, we can record _either_ a successful result, _or_ an exception. But in exception after success we want to record the successes up to the exception; and in a warning during a success we want to record the exception even though we return a success result.

The solution is similar in both cases: create a wrapper of the _primary type_ which can hold an instance of the _secondary type_.

In _exception after a success_ the primary type is an exception, and the secondary type is the result which was obtained up to that exception. The type will look like this:

```python
class AfterSuccessError(Exception):
    def __init__(self, result_before_error: Result):
        self.result_before_error = result_before_error
```

In _warning during success_, the primary type is the result, and the secondary type is the exception raised during successful processing which we consider a warning. This is the inverse of the above, and the types are therefore inverted too.

```python
@dataclasses.dataclass
class Result:
    value: Value
    warning: Exception | None
```

This could just as easily be a Pydantic class or whatever is appropriate in the situation, as long as it can hold the warning. If the warning is generated during an additional or side task, we can use `Outcome[SideValue]` instead. We do this, for example, in the type representing a linked committee:

```python
@dataclasses.dataclass
class LinkedCommittee:
    name: str
    autogenerated_keys_file: Outcome[str]
```

In this case, if the autogenerated keys file call succeeded without an error, the `Outcome` will be an `OutcomeResult[str]` where the `str` represents the full path to the autogenerated file.

## What makes this safe?

We can always open a database session or write to the filesystem, so there is no way to make storage access truly safe. But abstracting these operations to a well known interface makes it more likely that we use only this way of doing things, which we can then concentrate on getting right. This is in contrast to writing storage access in _ad hoc_ ways, some of which may be correct and some of which may not.

Code relative to a permissions level is only ever exposed in the storage interface when it is proven, at the type level and during runtime, that the user has credentials for those permissions. Helper code remains private due to the use of `__private_methods`, which undergo name mangling in Python. As mentioned in the introduction, the storage interface is also the suitable place to add audit logging, currently planned and not yet implemented.
