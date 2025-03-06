#!/usr/bin/env python3

import sys
import types

# This fix will be unnecessary once asfpy is released with:
# https://github.com/apache/infrastructure-asfpy/commit/330b223
# And ASFQuart is updated to use the updated asfpy
if sys.platform == "darwin":
    sys.modules["asyncinotify"] = types.ModuleType("asyncinotify")
    sys.modules["asyncinotify"]._ffi = types.ModuleType("_ffi")
    sys.modules["asyncinotify"].Inotify = type("Inotify", (), {"__init__": lambda *_: None})

# ensure all submodules are loaded
from . import config, base, session, utils

# This will be rewritten once construct() is called.
APP = None

# Lift the construction from base to the package level.
construct = base.construct
