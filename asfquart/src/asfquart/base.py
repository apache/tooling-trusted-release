#!/usr/bin/env python3

"""ASFQuart - Base application/event-loop module.

USAGE:

  main.py:
    import asfquart
    APP = asfquart.construct('selfserve')

  anywhere else:
    import asfquart
    APP = asfquart.APP


Quart.app defines a "name" property which can be used as an APP "ID"
(eg. discriminator for cookies). While most Quart apps use the module
name for this (and internally Quart calls this .import_name), it can
be anything and the .name property treats it as arbitrary.
"""

import sys
import asyncio
import pathlib
import secrets
import os
import stat
import logging
import signal

import asfpy.twatcher
import quart  # implies .app and .utils
import hypercorn.utils
import ezt
import easydict
import yaml
import watchfiles

import __main__
from . import utils

try:
    ExceptionGroup
except NameError:
    # This version does not have an ExceptionGroup (introduced in
    # Python 3.11). Somebody (hypercorn) might be using a backport
    # of it from the "exceptiongroup" package. We'll catch that
    # instead. Note that packages designed for less than 3.11
    # won't be throwing ExceptionGroup (of any form) at all, which
    # means our catching it will be a no-op.
    if sys.version_info < (3, 11):
        from exceptiongroup import ExceptionGroup

LOGGER = logging.getLogger(__name__)
SECRETS_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0o600, read/write for this user only
SECRETS_FILE_UMASK = 0o777 ^ SECRETS_FILE_MODE  # Prevents existing umask from mangling the mode
CONFIG_FNAME = 'config.yaml'


class ASFQuartException(Exception):
    """Global ASFQuart exception with a message and an error code, for the HTTP response."""

    def __init__(self, message: str = "An error occurred", errorcode: int = 500):
        self.message = message
        self.errorcode = errorcode
        super().__init__(self.message)


class QuartApp(quart.Quart):
    """Subclass of quart.Quart to include our specific features."""

    def __init__(self, app_id, *args, **kw):
        super().__init__(app_id, *args, **kw)

        # Locate the app dir as best we can. This is used for app ID
        # and token filepath generation
        # TODO: hypercorn does not have a __file__ variable available,
        # so we are forced to fall back to CWD. Maybe have an optional arg
        # for setting the app dir?
        if hasattr(__main__, "__file__"):
            self.app_dir = pathlib.Path(__main__.__file__).parent
        else:  # No __file__, probably hypercorn, fall back to cwd for now
            self.app_dir = pathlib.Path(os.getcwd())
        self.app_id = app_id

        # check if a path to a config file is given, otherwise default to CONFIG_FNAME
        self.cfg_path = self.app_dir / kw.pop("cfg_path", CONFIG_FNAME)

        # Most apps will require a watcher for their EZT templates.
        self.tw = asfpy.twatcher.TemplateWatcher()
        self.add_runner(self.tw.watch_forever, name=f"TW:{app_id}")

        # use an easydict for config values
        self.cfg = easydict.EasyDict()

        # token handler callback for PATs - see docs/sessions.md
        self.token_handler = None  # Default to no PAT handler available.

        # Read, or set and write, the application secret token for
        # session encryption. We prefer permanence for the session
        # encryption, but will fall back to a new secret if we
        # cannot write a permanent token to disk...with a warning!
        _token_filename = self.app_dir / "apptoken.txt"

        if os.path.isfile(_token_filename):  # Token file exists, try to read it
            # Test that permissions are as we want them, warn if not, but continue
            st = os.stat(_token_filename)
            file_mode = st.st_mode & 0o777
            if file_mode != SECRETS_FILE_MODE:
                sys.stderr.write(
                    f"WARNING: Secrets file {_token_filename} has file mode {oct(file_mode)}, we were expecting {oct(SECRETS_FILE_MODE)}\n"
                )
            self.secret_key = open(_token_filename).read()
        else:  # No token file yet, try to write, warn if we cannot
            self.secret_key = secrets.token_hex()
            ### TBD: throw the PermissionError once we stabilize how to locate
            ### the APP directory (which can be thrown off during testing)
            try:
                # New secrets files should be created with chmod 600, to ensure that only
                # the app has access to them. umask is recorded and changed during this, to 
                # ensure we don't have umask overriding what we want to achieve.
                umask_original = os.umask(SECRETS_FILE_UMASK)  # Set new umask, log the old one
                try:
                    fd = os.open(_token_filename, flags=(os.O_WRONLY | os.O_CREAT | os.O_EXCL), mode=SECRETS_FILE_MODE)
                finally:
                    os.umask(umask_original)  # reset umask to the original setting
                with open(fd, "w") as sfile:
                    sfile.write(self.secret_key)
            except PermissionError:
                LOGGER.error(f"Could not open {_token_filename} for writing. Session permanence cannot be guaranteed!")

    def runx(self, /,
             host="0.0.0.0", port=None,
             debug=True, loop=None,
             certfile=None, keyfile=None,
             extra_files=frozenset(), # OK, because immutable
             ):
        """Extended version of Quart.run()

        LOOP is the loop this app should run within. One will be constructed,
        if this is not provided.

        EXTRA_FILES is a set of files (### relative to?) that should be
        watched for changes. If a change occurs, the app will be reloaded.
        """

        # Default PORT is None, but it must be explicitly specified.
        assert port, "The port must be specified."

        # NOTE: much of the code below is direct from quart/app.py:Quart.run()
        # This local "copy" is to deal with the custom watcher/reloader.

        if loop is None:
            loop = asyncio.new_event_loop()
            loop.set_debug(debug)

            asyncio.set_event_loop(loop)

        # Create a factory for a trigger that watches for exceptions.
        trigger = self.factory_trigger(loop, extra_files)

        # Construct a task to run the app.
        task = self.run_task(
            host,
            port,
            debug,
            certfile=certfile,
            keyfile=keyfile,
            shutdown_trigger=trigger,
        )

        ### LOG/print some info about the app starting?
        print(f' * Serving Quart app "{self.app_id}"')
        print(f" * Debug mode: {self.debug}")
        print(" * Using reloader: CUSTOM")
        print(f" * Running on http://{host}:{port}")
        print(" * ... CTRL + C to quit")

        # Ready! Start running the app.
        self.run_forever(loop, task)
        # Being here, means graceful exit.

    def factory_trigger(self, loop, extra_files=frozenset()):
        """Factory for an AWAITABLE that handles special exceptions.

        The LOOP normally ignores all signals. This method will make the
        loop catch SIGTERM/SIGINT, then set an Event to raise an exception
        for a clean exit.

        This will also observe files for changes, and signal the loop
        to reload the application.
        """

        # Note: Quart.run() allows for optional signal handlers. We do not.

        shutdown_event = asyncio.Event()
        def _shutdown_handler(*_) -> None:
            shutdown_event.set()
        loop.add_signal_handler(signal.SIGTERM, _shutdown_handler)
        loop.add_signal_handler(signal.SIGINT, _shutdown_handler)
        async def shutdown_wait():
            "Log a nice message when we're signalled to shut down."
            await shutdown_event.wait()
            LOGGER.info('SHUTDOWN: Performing graceful exit...')
            gathered.cancel()
            raise hypercorn.utils.ShutdownError()

        restart_event = asyncio.Event()
        def _restart_handler(*_) -> None:
            restart_event.set()
        loop.add_signal_handler(signal.SIGUSR2, _restart_handler)
        async def restart_wait():
            "Log a nice message when we're signalled to restart."
            await restart_event.wait()
            LOGGER.info('RESTART: Performing process restart...')
            gathered.cancel()
            raise quart.utils.MustReloadError()

        # Normally, for the SHUTDOWN_TRIGGER, it simply completes and
        # returns (eg. waiting on an event) as it gets wrapped into
        # hypercorn.utils.raise_shutdown() to raise ShutdownError.
        #
        # We are gathering three tasks, each running forever until its
        # condition raises an exception.
        #
        # .watch() will raise MustReloadError
        # shutdown_wait() will raise ShutdownError
        # restart_wait() will raise MustReloadError
        t1 = loop.create_task(self.watch(extra_files),
                              name=f'Watch:{self.app_id}')
        t2 = loop.create_task(shutdown_wait(),
                              name=f'Shutdown:{self.app_id}')
        t3 = loop.create_task(restart_wait(),
                              name=f'Restart:{self.app_id}')
        aw = asyncio.gather(t1, t2, t3)

        gathered = utils.CancellableTask(aw, loop=loop,
                                         name=f'Trigger:{self.app_id}')
        async def await_gathered():
            await gathered.task

        return await_gathered  # factory to create an awaitable (coro)

    async def watch(self, extra_files=frozenset()):
        "Watch all known .py files, plus some extra files (eg. configs)."

        py_files = set(getattr(m, "__file__", None) for m in sys.modules.values())
        py_files.remove(None)  # the built-in modules

        if os.path.isfile(self.cfg_path):
            cfg_files = { self.cfg_path }
        else:
            cfg_files = set()

        watched_files = py_files | cfg_files | extra_files

        # quiet down the watchfiles logger
        logging.getLogger('watchfiles.main').setLevel(logging.INFO)

        async for changes in watchfiles.awatch(*watched_files):
            for event in changes:
                if (event[0] == watchfiles.Change.modified or event[0] == watchfiles.Change.deleted or event[0] == watchfiles.Change.added):
                    LOGGER.info(f"File changed: {event[1]}")
                    raise quart.utils.MustReloadError
        # NOTREACHED

    def run_forever(self, loop, task):
        "Run the application until exit, then cleanly shut down."

        # Note: this logic is copied from quart/app.py
        reload_ = False
        try:
            loop.run_until_complete(task)
        except quart.utils.MustReloadError:
            reload_ = True
            LOGGER.debug('FOUND: MustReloadError')
        except ExceptionGroup as e:
            reload_ = (e.subgroup(quart.utils.MustReloadError) is not None)
            LOGGER.debug(f'FOUND: ExceptionGroup, reload_={reload_}')
        finally:
            try:
                quart.app._cancel_all_tasks(loop) # pylint: disable=protected-access
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                asyncio.set_event_loop(None)
                loop.close()
        if reload_:
            quart.utils.restart()

    def load_template(self, tpath, base_format=ezt.FORMAT_HTML):
        # Use str() to avoid passing Path instances.
        return self.tw.load_template(str(self.app_dir / tpath), base_format=base_format)

    def use_template(self, path_or_T, base_format=ezt.FORMAT_HTML):
        # Decorator to use a template, specified by path or provided.

        if isinstance(path_or_T, ezt.Template):
            return utils.use_template(path_or_T)

        return utils.use_template(self.load_template(path_or_T, base_format))

    def add_runner(self, func, name=None):
        "Add a long-running task, with cancellation/cleanup."

        # NOTES:
        #
        # We take advantage of the WHILE_SERVING mechanism that uses a
        # generator to manage the lifecycle of a task. We create/schedule
        # a task when the app starts up, then yield back to the framework.
        # Control returns when the app is shutting down, and we can cleanly
        # cancel the long-running task.
        #
        # Contrast this with APP.background_tasks. Each task placed into
        # that set must monitor APP.shutdown_event to know when the task
        # should exit (or an external mechanism observing that event must
        # cancel the task). The coordination becomes more difficult, and
        # must be handled by the application logic. The WHILE_SERVING
        # mechanism used here places no demands upon the caller to manage
        # the lifecycle of the long-running task.
        #
        # Further note: should a task be placed into APP.background_tasks,
        # it will be waited on to exit at shutdown time. If the task is
        # not watching APP.shutdown_event, and does not complete, finish,
        # or cancel within a timeout period (default is 5 seconds), then
        # that background task is canceled. That is an unstructured
        # completion/cancellation mechanism and introduces a delay during
        # the shutdown process.

        @self.while_serving
        async def perform_runner():
            ctask = utils.CancellableTask(func(), name=name)
            #print('RUNNER STARTED:', ctask.task)

            yield  # back to serving

            #print('RUNNER STOPPING:', ctask.task)
            ctask.cancel()


def construct(name, *args, **kw):
    ### add/alter/update ARGS and KW for our specific preferences

    # By default, we will set up OAuth and force login redirect on auth failure
    # This can be turned off by setting oauth=False in the construct call.
    # To use a different oauth URI than the default /auth, specify the URI
    # in the oauth argument, for instance: asfquart.construct("myapp", oauth="/session")
    # Pop the arguments from KW, as the parent class doesn't understand them.
    setup_oauth = kw.pop("oauth", True)
    # Note: order is important, as we want the .pop() to always execute.
    force_auth_redirect = kw.pop("force_login", True) and setup_oauth

    app = QuartApp(name, *args, **kw)

    @app.errorhandler(ASFQuartException)  # ASFQuart exception handler
    async def handle_exception(error):
        # If an error is thrown before the request body has been consumed, eat it quietly.
        if not quart.request.body._complete.is_set():  # pylint: disable=protected-access
            async for _data in quart.request.body:
                pass
        return quart.Response(status=error.errorcode, response=error.message)

    # try to load the config information from app.cfg_path
    if os.path.isfile(app.cfg_path):
        app.cfg.update(yaml.safe_load(open(app.cfg_path)))

    # Provide our standard filename argument converter.
    import asfquart.utils

    # Sane defaults for cookies: SameSite=Strict; Secure; HttpOnly
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True

    app.url_map.converters["filename"] = asfquart.utils.FilenameConverter

    # Set up oauth and login redirects if needed
    if setup_oauth:
        import asfquart.generics

        # Figure out the OAuth URI we want to use.
        oauth_uri = setup_oauth if isinstance(setup_oauth, str) else asfquart.generics.DEFAULT_OAUTH_URI
        asfquart.generics.setup_oauth(app, uri=oauth_uri)
        if force_auth_redirect:
            asfquart.generics.enforce_login(app, redirect_uri=oauth_uri)

    # Now stash this into the package module, for later pick-up.
    asfquart.APP = app

    return app
