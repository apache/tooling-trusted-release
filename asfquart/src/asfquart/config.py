#!/usr/bin/env python3

"""ASFQuart - Configuration readers"""

import yaml
import functools
import inspect

DEFAULT_CONFIG_FILENAME = "config.yaml"


async def _read_config(callback, config_filename):
    """Reads a YAML configuration and passes it to the callback"""
    with open(config_filename, encoding='utf-8') as r:
        config_as_dict = yaml.safe_load(r)
    # Some configuration routines may require os to block while the configuration is applied, so
    # we will accept both sync and async callbacks.
    # If the callback is async, await it...
    if inspect.iscoroutinefunction(callback):
        await callback(config_as_dict)
    # Otherwise, just run it in blocking mode
    else:
        callback(config_as_dict)


def static(func):
    """Standard wrapper for a configuration parser. Reads config.yaml and passes it to the callback as a dict"""

    @functools.wraps(func)
    async def config_wrapper(config_filename=DEFAULT_CONFIG_FILENAME):
        await _read_config(func, config_filename)

    return config_wrapper
