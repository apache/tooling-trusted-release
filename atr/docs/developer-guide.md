# 2. Developer guide

**Up**: [Apache Trusted Releases documentation](.)
**Prev**: 1. [Introduction to ATR](introduction-to-atr)

This is a guide for developers of ATR, explaining how to make changes to the ATR source code. For more information about how to contribute those changes back to us, please read the [contribution guide](contribution-guide) instead.

## Running the server

To develop ATR locally, we manage dependencies using [uv](https://docs.astral.sh/uv/). To run ATR on ASF hardware, we run it in containers managed by Puppet, but since this guide is about development, we focus on using uv.

### Get the source

[Fork the source code](https://github.com/apache/tooling-trusted-releases/fork) of [ATR on GitHub](https://github.com/apache/tooling-trusted-releases), and then [clone your fork locally](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository).

There are lots of files and directories in the root of the ATR Git repository. The most important thing to know is that `atr/` contains the source code. ATR is a Python application based on [ASFQuart](https://github.com/apache/infrastructure-asfquart), which is based on [Quart](https://github.com/pallets/quart). The Quart web framework is an asynchronous version of [Flask](https://github.com/pallets/flask), a very widely used synchronous web framework. In addition to Python, we use small amounts of JavaScript and TypeScript for the front end.

### Install dependencies

To run ATR locally after cloning the source, you will need to install the following dependencies:

* Any [POSIX](https://en.wikipedia.org/wiki/POSIX) compliant [make](https://frippery.org/make/)
* [mkcert](https://github.com/FiloSottile/mkcert)
* [Python 3.13](https://www.python.org/downloads/release/python-3138/)
* [uv](https://docs.astral.sh/uv/#installation)

You can install Python 3.13 through your package manager or through uv. Here is how to install these dependencies on [Alpine Linux](https://en.wikipedia.org/wiki/Alpine_Linux):

```shell
apk add curl git make mkcert@testing
curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh
uv python install 3.13
```

You do not need to have Alpine Linux to develop ATR. It should work in any POSIX style environment.

### Run the server

Then, to run the server:

```shell
cd tooling-trusted-releases/
mkdir state
make certs-local
make serve-local
```

The `certs-local` step runs `mkcert localhost.apache.org localhost 127.0.0.1 ::1` to generate a locally trusted TLS certificate. If the certificate is not trusted, you may have to follow the [mkcert guide](https://github.com/FiloSottile/mkcert/blob/master/README.md) to resolve the issue.

ATR requires TLS even for development because login is performed through the actual ASF OAuth server. This way, the development behavior aligns closely with the production behavior. We try to minimize differences between development and production environments.

### Load the site

ATR will then be served on various hosts, but we recommend using only `localhost.apache.org`. This requires adding an entry to your `/etc/hosts` and potentially restarting your DNS server. If you do this, the following link should work:

[`https://localhost.apache.org:8080/`](https://localhost.apache.org:8080/)

If you do not want to change your `/etc/hosts`, you can use `127.0.0.1`. You should not use `localhost`. The following link should work:

[`https://127.0.0.1:8080/`](https://127.0.0.1:8080/)

Pick one or the other, because logging into the site on one host does not log you in to the site on any other host.

## Understanding the code

Once you have the server running, you can test it. At this point, it is useful to understand how the ATR works in general.

ATR is an [ASFQuart](https://github.com/apache/infrastructure-asfquart) application, running in [Hypercorn](https://hypercorn.readthedocs.io/en/latest/index.html). The entry point for Hypercorn is [`atr.server:app`](/ref/atr/server.py:app), which is then called with a few standard arguments [as per the ASGI specification](https://asgi.readthedocs.io/en/latest/specs/main.html#overview). We create the `app` object using the following code:

```python
app = create_app(config.get())
```

The [`create_app`](/ref/atr/server.py:create_app) function performs a lot of setup, and if you're interested in how the server works then you can read it and the functions it calls to understand the process further. In general, however, when developing ATR we do not work at the ASFQuart, Quart, and Hypercorn levels very often.
