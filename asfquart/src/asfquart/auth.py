#!/usr/bin/env python3
"""ASFQuart - Authentication methods and decorators"""
from . import base, session
import functools
import typing
import asyncio
import collections.abc

class Requirements:
    """Various pre-defined access requirements"""

    # Error messages related to tests
    E_NOT_LOGGED_IN = "You need to be logged in to access this endpoint."
    E_NOT_MEMBER = "This endpoint is only accessible to foundation members."
    E_NOT_CHAIR = "This endpoint is only accessible to project chairs."
    E_NO_MFA = "This endpoint requires you to log on using multi-factor authentication."
    E_NOT_ROOT = "This endpoint is only accessible to foundation staff."
    E_NOT_PMC = "This endpoint is only accessible to members of the foundation committees."
    E_NOT_ROLEACCOUNT = "This endpoint is only accessible to role accounts."
    

    @classmethod
    def mfa_enabled(cls, client_session: session.ClientSession):
        """Tests for MFA enabled in the client session"""
        return isinstance(client_session, session.ClientSession) and client_session.mfa is True, cls.E_NO_MFA

    @classmethod
    def committer(cls, client_session: session.ClientSession):
        """Tests for whether the user is a committer on any project"""
        return isinstance(client_session, session.ClientSession), cls.E_NOT_LOGGED_IN

    @classmethod
    def member(cls, client_session: session.ClientSession):
        """Tests for whether the user is a foundation member"""
        # Anything but True will cause a failure.
        return client_session.isMember is True, cls.E_NOT_MEMBER

    @classmethod
    def chair(cls, client_session: session.ClientSession):
        """tests for whether the user is a chair of any top-level project"""
        # Anything but True will cause a failure.
        return client_session.isChair is True, cls.E_NOT_CHAIR

    @classmethod
    def root(cls, client_session: session.ClientSession):
        """tests for whether the user is a member of infra-root"""
        # Anything but True will cause a failure.
        return client_session.isRoot is True, cls.E_NOT_ROOT

    @classmethod
    def pmc_member(cls, client_session: session.ClientSession):
        """tests for whether the user is a PMC member of any top-level project"""
        # Anything but True will cause a failure.
        return bool(client_session.committees), cls.E_NOT_PMC    

    @classmethod
    def roleacct(cls, client_session: session.ClientSession):
        """tests for whether the user is a service account"""
        # Anything but True will cause a failure.
        return client_session.isRole is True, cls.E_NOT_ROLEACCOUNT

class AuthenticationFailed(base.ASFQuartException):
    def __init__(self, message: str = "Authentication failed", errorcode: int = 403):
        self.message = message
        self.errorcode = errorcode
        super().__init__(self.message, self.errorcode)


def requirements_to_iter(args: typing.Any):
    """Converts any auth req args (single arg, list, tuple) to an iterable if not already one"""
    # No args? return empty list
    if args is None:
        return []
    # Single arg? Convert to list first
    if not isinstance(args, collections.abc.Iterable):
        args = [args]
    # Test that each requirement is an allowed one (belongs to the Requirements class)
    for req in args:
        if not callable(req) or req != getattr(Requirements, req.__name__, None):
            raise TypeError(
                f"Authentication requirement {req} is not valid. Must belong to the asfquart.auth.Requirements class."
            )
    return args


def require(
    func: typing.Optional[typing.Callable] = None,
    all_of: typing.Optional[typing.Iterable] = None,
    any_of: typing.Optional[typing.Iterable] = None,
):
    """Adds authentication/authorization requirements to an endpoint. Can be a single requirement or a list
    of requirements. By default, all requirements must be satisfied, though this can be made optional by
    explicitly using the `all_of` or `any_of` keywords to specify optionality. Requirements must be part
    of the asfquart.auth.Requirements class, which consists of the following test:

    - mfa_enabled: The client must authenticate with a method that has MFA enabled
    - committer: The client must be a committer
    - member: The client must be a foundation member
    - chair: The client must be a chair of a project

    In addition, any endpoint decorated with @require will implicitly require ANY form of
    authenticated session. This is mandatory and also works as a bare decorator.

    Examples:
        @require(Requirements.member)  # Require session, require ASF member
        @require  # Require any authed session
        @require({Requirements.mfa_enabled, Requirements.chair})  # Require any project chair with MFA-enabled session
        @require(all_of=Requirements.mfa_enabled, any_of={Requirements.member, Requirements.chair})
          # Require either ASF member OR project chair, but also require MFA enabled in any case.
    """

    async def require_wrapper(func: typing.Callable, all_of=None, any_of=None, *args, **kwargs):
        client_session = await session.read()
        errors_list = []
        # First off, test if we have a session at all.
        if not isinstance(client_session, dict):
            raise AuthenticationFailed(Requirements.E_NOT_LOGGED_IN)

        # Test all_of
        all_of_set = requirements_to_iter(all_of)
        for requirement in all_of_set:
            passes, desc = requirement(client_session)
            if not passes:
                errors_list.append(desc)
        # If we encountered an error, bail early
        if errors_list:
            raise AuthenticationFailed("\n".join(errors_list))

        # So far, so good? Run the any_of if present, break if any single test succeeds.
        any_of_set = requirements_to_iter(any_of)
        for requirement in any_of_set:
            passes, desc = requirement(client_session)
            if not passes:
                errors_list.append(desc)
            else:
                # If a test passed, we can clear the failures and pass
                errors_list.clear()
                break
        # If no tests passed, errors_list should have at least one entry.
        if errors_list:
            raise AuthenticationFailed("\n".join(errors_list))
        if args or kwargs:
            return await func(*args, **kwargs)
        return await func()

    # If decorator is passed without arguments, func will be an async function
    # In this case, we will return a simple wrapper.
    if asyncio.iscoroutinefunction(func):
        return functools.wraps(func)(functools.partial(require_wrapper, func))

    # If passed with args, we construct a "double wrapper" and return it.
    def require_with_args(original_func: typing.Callable):
        # If decorated without keywords, func disappears in the outer scope and is replaced with all_of,
        # so we account for this by swapping around the arguments just in time if needed.
        if not asyncio.iscoroutinefunction(func):
            return functools.wraps(original_func)(
                functools.partial(
                    require_wrapper,
                    original_func,
                    all_of=requirements_to_iter(all_of or func),
                    any_of=requirements_to_iter(any_of),
                )
            )
        return functools.wraps(original_func)(
            functools.partial(
                require_wrapper, original_func, all_of=requirements_to_iter(all_of), any_of=requirements_to_iter(any_of)
            )
        )

    return require_with_args
