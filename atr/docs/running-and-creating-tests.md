# 3.7. Running and creating tests

**Up**: `3.` [Developer guide](developer-guide)

**Prev**: `3.6.` [Build processes](build-processes)

**Next**: `3.8.` [Code conventions](code-conventions)

**Sections**:

* [Running tests](#running-tests)
* [Creating tests](#creating-tests)

## Running tests

We currently only have end-to-end browser tests, but we plan to expand these as part of [Issue #209](https://github.com/apache/tooling-trusted-releases/issues/209). Meanwhile, these browser tests serve as a simple consistency check when developing ATR.

To run the tests, you will need Docker. Other OCI runtimes should work, but you will need to edit the [`Makefile`](/ref/Makefile) or run your own command. The simple way to run the tests is:

```shell
make build-playwright && make run-playwright
```

Where the two `make` invocations correspond to:

```shell
docker build -t atr-playwright -f tests/Dockerfile.playwright playwright
docker run --net=host -it atr-playwright python3 test.py --skip-slow
```

In other words, we build [`tests/Dockerfile.playwright`](/ref/tests/Dockerfile.playwright), and then run [`playwright/test.py`](/ref/playwright/test.py) inside that container. The container is called `atr-playwright`; if you want to give the container a different name, then you'll need to run the manual `docker` commands. Replace `docker` with the name of your Docker-compatible OCI runtime to use an alternative runtime.

The tests should, as of 14 Oct 2025, take about 20 to 25 seconds to run. The last line should be `Tests finished successfully`, and if the tests do not complete successfully there should be an obvious Python backtrace.

## Creating tests

You can add tests to `playwright/test.py`. If you're feeling particularly adventurous, you can add separate unit tests etc., but it's okay to add tests only to the Playwright test script until [Issue #209](https://github.com/apache/tooling-trusted-releases/issues/209) is resolved.

### How the tests work

The browser tests use [Playwright](https://playwright.dev/), which is a cross-browser, cross-platform web testing framework. It's a bit like the older [PhantomJS](https://en.wikipedia.org/wiki/PhantomJS), now discontinued, which allows you to operate a browser through scripting. Playwright took the same concept and improved the user experience by adding better methods for polling browser state. Most interactions with a browser take some time to complete, and in PhantomJS the developer had to do that manually. Playwright makes it easier, and has become somewhat of an industry standard for browser tests.

We use the official Playwright OCI container, install a few dependencies (`apt-get` is available in the container), and then run `test.py`.

The `test.py` script calls [`run_tests`](/ref/playwright/test.py:run_tests) from its `main`, which sets up all the context, but the main action takes place in [`test_all`](/ref/playwright/test.py:test_all). This function removes any state accidentally left over from a previous run, then runs tests of certain components. Because ATR is stateful, the order of the tests is important. When adding a test, please be careful to ensure that you use the correct state and that you try not to modify that state in such a way that interferes with tests placed afterwards.

We want to make it more clear which Playwright tests depend on which, and have more isolated tests. Reusing context, however, helps to speed up the tests.

The actual test cases themselves tend to use helpers such as [`go_to_path`](/ref/playwright/test.py:go_to_path) and [`wait_for_path`](/ref/playwright/test.py:wait_for_path), and then call [`logging.info`](https://docs.python.org/3/library/logging.html#logging.info) to print information to the console. Try to keep logging messages terse and informative.
