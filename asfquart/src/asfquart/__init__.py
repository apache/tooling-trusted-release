#!/usr/bin/env python3

import sys
import types

if sys.platform == "darwin":
    # Create a dummy module for asyncinotify._ffi
    dummy_ffi = types.ModuleType("_ffi")

    def dummy_inotify_init():
        raise NotImplementedError("inotify is not supported on macOS")

    dummy_ffi.inotify_init = dummy_inotify_init  # type: ignore

    # Define a dummy Inotify class with no-op methods
    class DummyInotify:
        def __init__(self, *args, **kwargs):
            pass

        def fileno(self):
            return -1

        def read(self, *args, **kwargs):
            return b""

        def close(self):
            pass

    # Create a dummy asyncinotify module that contains our dummy _ffi and Inotify
    dummy_asyncinotify = types.ModuleType("asyncinotify")
    dummy_asyncinotify._ffi = dummy_ffi  # type: ignore
    dummy_asyncinotify.Inotify = DummyInotify  # type: ignore

    # Insert our dummy module into sys.modules so future imports use it
    sys.modules["asyncinotify"] = dummy_asyncinotify

# ensure all submodules are loaded
from . import config, base, session, utils

# This will be rewritten once construct() is called.
APP = None

# Lift the construction from base to the package level.
construct = base.construct
