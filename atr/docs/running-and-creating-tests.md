# 3.7. Running and creating tests

**Up**: `3.` [Developer guide](developer-guide)

**Prev**: `3.6.` [Build processes](build-processes)

**Next**: `3.8.` [Code conventions](code-conventions)

**Sections**:

* [Running tests](#running-tests)
* [Creating tests](#creating-tests)

## Running tests

We currently only have end-to-end browser tests, but we plan to expand these as part of [Issue #209](https://github.com/apache/tooling-trusted-releases/issues/209). Meanwhile, these browser tests serve as a simple consistency check when developing ATR.

To run the tests, you will need Docker. Other OCI runtimes should work, but you will need to edit the test scripts accordingly.

### Using Docker Compose

The simplest way to run the tests is using Docker Compose, which starts both ATR and the Playwright test container:

```shell
sh tests/run-tests.sh
```

This uses [`tests/docker-compose.yml`](/ref/tests/docker-compose.yml) to orchestrate the test environment. The ATR server runs in one container and the Playwright tests run in another, connected via a Docker network.

### Using host networking

If you already have ATR running locally with `make serve-local`, you can run the Playwright tests directly against it instead of using Docker Compose:

```shell
make build-playwright && make run-playwright
```

Where the two `make` invocations correspond to:

```shell
docker build -t atr-playwright -f tests/Dockerfile.playwright playwright
docker run --net=host -it atr-playwright python3 test.py --skip-slow
```

In other words, we build [`tests/Dockerfile.playwright`](/ref/tests/Dockerfile.playwright), and then run [`playwright/test.py`](/ref/playwright/test.py) inside that container using host networking to access your locally running ATR instance. Replace `docker` with the name of your Docker-compatible OCI runtime to use an alternative runtime.

### Test duration

The tests should, as of 14 Oct 2025, take about 40 to 50 seconds to run in Docker Compose, and 20 to 25 seconds to run on the host. The last line of the test output should be `Tests finished successfully`, and if the tests do not complete successfully there should be an obvious Python backtrace.

## Creating tests

You can add tests to `playwright/test.py`. If you're feeling particularly adventurous, you can add separate unit tests etc., but it's okay to add tests only to the Playwright test script until [Issue #209](https://github.com/apache/tooling-trusted-releases/issues/209) is resolved.

### How the tests work

The browser tests use [Playwright](https://playwright.dev/), which is a cross-browser, cross-platform web testing framework. It's a bit like the older [PhantomJS](https://en.wikipedia.org/wiki/PhantomJS), now discontinued, which allows you to operate a browser through scripting. Playwright took the same concept and improved the user experience by adding better methods for polling browser state. Most interactions with a browser take some time to complete, and in PhantomJS the developer had to do that manually. Playwright makes it easier, and has become somewhat of an industry standard for browser tests.

We use the official Playwright OCI container, install a few dependencies (`apt-get` is available in the container), and then run `test.py`.

The `test.py` script calls [`run_tests`](/ref/playwright/test.py:run_tests) from its `main`, which sets up all the context, but the main action takes place in [`test_all`](/ref/playwright/test.py:test_all). This function removes any state accidentally left over from a previous run, then runs tests of certain components. Because ATR is stateful, the order of the tests is important. When adding a test, please be careful to ensure that you use the correct state and that you try not to modify that state in such a way that interferes with tests placed afterwards.

We want to make it more clear which Playwright tests depend on which, and have more isolated tests. Reusing context, however, helps to speed up the tests.

The actual test cases themselves tend to use helpers such as [`go_to_path`](/ref/playwright/test.py:go_to_path) and [`wait_for_path`](/ref/playwright/test.py:wait_for_path), and then call [`logging.info`](https://docs.python.org/3/library/logging.html#logging.info) to print information to the console. Try to keep logging messages terse and informative.
