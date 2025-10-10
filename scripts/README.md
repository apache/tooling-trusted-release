# ATR utility scripts

Many of these scripts are intended to be used by other scripts, or by `Makefile` targets.

## generate-certificates

Generates self signed SSL certificates for development and testing purposes. It creates a private RSA key and a certificate valid for `127.0.0.1` with a one year expiration period, and stores them in the state directory as `cert.pem` and `key.pem`.

## poetry/add-dev

Provides a wrapper around Poetry's package management system, allowing the user to add development dependencies. It executes the `poetry add --group dev` command with the specified package. This script can be used to add new development tools, test libraries, or other dependencies that are only needed during development and not in production environments.

## poetry/add

Wraps Poetry's package management system, allowing the user to add main, i.e. non-development, dependencies to the project. It executes the `poetry add` command with the specified package name.

## poetry/sync-dev

Configures and synchronises the Poetry development environment by ensuring that the correct Python interpreter is used, updating the lock file, and synchronising all dependencies. It also generates VSCode configuration settings if a `.vscode` directory exists, adding the Poetry virtual environment to its Python path and setting its default interpreter.

## poetry/up

Updates all dependencies in the Poetry environment to their latest versions according to the specified constraints. It first ensures the correct Python interpreter is being used, and then executes `poetry update` to refresh all packages.

## poetry/build

Verifies that the application can be successfully containerised by building Docker images using both Alpine and Ubuntu base images. It runs the Docker build process with the tag `tooling-trusted-releases` for each Dockerfile, ensuring that the application builds correctly across different Linux distributions.

## poetry/run

Executes commands within the Poetry managed virtual environment by passing all provided arguments to the `poetry run` command. This allows developers to run any command or script in the context of the project's virtual environment without having to activate it manually, providing a consistent execution context regardless of the developer's system setup. When committing to the project, for example, it is necessary to run `git commit` as `poetry run git commit` in order to use consistent pre-commit hook dependencies.

## poetry/sync

Configures and synchronises the main Poetry dependencies, only, for production environments. It ensures that the correct Python interpreter is used, updates the lock file, and then synchronises the main dependencies, without development packages, using `poetry sync --only main`. This results in a smaller environment, suitable for production deployments.

## build

Builds a Docker container for the application using an Alpine Linux base image, and configures it to listen on port `4443` across all network interfaces (`0.0.0.0`). The resulting image is tagged as `tooling-trusted-releases`.


## release\_path\_parse.py

Parses a list of filename paths obtained from running `find -type f | sort | sed 's%^[.]/%%'` in `https://dist.apache.org/repos/dist/release/` into a form where heuristically detected elements are replaced with `VARIABLE` names. The complete list of element variables is: `ASF`, `SUB`, `VERSION`, `CORE`, `VARIANT`, `TAG`, `ARCH`, `EXT`, and (when `LABEL_MODE=1` is set) `LABEL`.

Excerpt from example output:

```
--- age ---

  VERSIONS: 1.1.0, 1.5.0
  SUBS: PG11, PG12, PG13, PG14, PG15, PG16, age-viewer

   21 ASF-CORE-VERSION-VARIANT.EXT
    3 ASF-SUB-TAG-rc2-incubating-VARIANT.EXT


--- airavata ---

  VERSIONS: 0.17, 1.1
  SUBS: custos

    8 ASF-CORE-SUB-VERSION-VARIANT.EXT
    6 ASF-CORE-server-VERSION-VARIANT.EXT
    3 CORE-VERSION-VARIANT.EXT
    5 SUB-VERSION-VARIANT.EXT
```

## run

Runs the application, configured for production use, in a Docker container. It launches a detached container that removes itself when stopped, mounts a state directory from the host system to persist data, and uses host networking to simplify port access.
