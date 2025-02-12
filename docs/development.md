# Development

You will need to have a working [Python 3.13](https://www.python.org/downloads/release/python-3132/) installation, [Poetry](https://python-poetry.org/docs/#installation), and a POSIX compliant `make`. To optionally build the HTML documentation files you will also need [cmark](https://github.com/commonmark/cmark).

Ensure that you have the pre-commit hook installed:

```shell
make sync PYTHON="$(which python3)"
poetry run pre-commit install
```

To run the project, use the following commands:

```shell
make sync PYTHON="$(which python3)"
make certs
make serve
```

The website will be available at [https://127.0.0.1:8080/](https://127.0.0.1:8080/) using a self-signed certificate.
