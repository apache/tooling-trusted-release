#!/usr/bin/env python3
"""Miscellaneous helpers for ASFQuart"""

import os.path
import io
import functools
import asyncio
import logging

import quart
import werkzeug.routing

LOGGER = logging.getLogger(__name__)

DEFAULT_MAX_CONTENT_LENGTH = 102400


async def formdata():
    """Catch-all form data converter. Converts form data of any form (json, urlencoded, mime, etc) to a dict"""
    form_data = dict()
    form_data.update(quart.request.args.to_dict())  # query string args
    xform = await quart.request.form                # POST form data
    # Pre-parse check for form data size
    if quart.request.content_type and any(
            x in quart.request.content_type
            for x in (
                    "multipart/form-data",
                    "application/x-www-form-urlencoded",
                    "application/x-url-encoded",
            )
    ):
        # If the content is too large for us to handle, we need to silently ignore every chunk, so we can return with a
        # cleared buffer, lest bad things happen.
        max_size = quart.current_app.config.get("MAX_CONTENT_LENGTH", DEFAULT_MAX_CONTENT_LENGTH)
        if quart.request.content_length > max_size:
            async for _data in quart.request.body:
                pass
            return quart.Response(
                status=413,
                response=f"Request content length ({quart.request.content_length} bytes) is larger than what is permitted for form data ({max_size} bytes)!",
            )
    if xform:
        form_data.update(xform.to_dict())
    if quart.request.is_json:  # JSON data from a PUT?
        xjson = await quart.request.json
        form_data.update(xjson)
    return form_data


class FilenameConverter(werkzeug.routing.BaseConverter):
    """Simple converter that splits a filename into a basename and an extension. Only deals with filenames, not
    full paths. Thus, <filename> will match foo.txt, but not /foo/bar.baz"""

    regex = r"^[^/.]*(\.[A-Za-z0-9]+)?$"
    part_isolating = False

    def to_python(self, filename): # pylint: disable=arguments-renamed
        return os.path.splitext(filename) # superclass function uses 'value'


#
# Decorator to use a template in order to generate a webpage with some
# provided data.
#
# EXAMPLE:
#
#   @use_template(T_MAIN)
#   def main_page():
#       ...
#       data = {
#           'title': 'Main Page',
#           'count': 42,
#       }
#       return data
#
# The data dictionary will be provided to the EZT template for
# rendering the page.
#
def use_template(template):

    # The @use_template(T_MAIN) example is actually a function call
    # to *produce* a decorator function. This is that decorator. It
    # takes a function to wrap (FUNC), and produces a wrapping function
    # that will be used during operation (WRAPPER).
    def decorator(func):

        # .wraps() copies name/etc from FUNC onto the wrapper function
        # that we return.
        @functools.wraps(func)
        async def wrapper(*args, **kw):
            # Get the data dictionary from the page endpoint.
            data = await func(*args, **kw)

            # Render that page, and return it to Quart.
            return render(template, data)

        return wrapper

    return decorator


def render(t, data):
    "Simple function to render a template into a string."
    buf = io.StringIO()
    t.generate(buf, data)
    return buf.getvalue()


class CancellableTask:
    "Wrapper for a task that does not propagate its cancellation."

    def __init__(self, coro, *, loop=None, name=None):
        "Create a task for CORO in LOOP, named NAME."

        if loop is None:
            loop = asyncio.get_event_loop()

        async def absorb_cancel():
            try:
                await coro
            except asyncio.CancelledError:
                LOGGER.debug(f'TASK CANCELLED: {self.task}')

        self.task = loop.create_task(absorb_cancel(), name=name)

    def cancel(self):
        "Cancel the task, and clean up its CancelledError exception."

        self.task.cancel()
