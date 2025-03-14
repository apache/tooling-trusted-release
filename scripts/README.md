# ATR utility scripts

Many of these scripts are intended to be used by other scripts, or by `Makefile` targets.

## generate-certificates

Generates self signed SSL certificates for development and testing purposes. It creates a private RSA key and a certificate valid for `127.0.0.1` with a one year expiration period, and stores them in the state directory as `cert.pem` and `key.pem`. These certificates enable HTTPS to work when running the application locally, allowing developers to test the application with SSL encryption without needing to obtain certificates from a certificate authority. Signing in using ASF OAuth does not work without the use of HTTPS, so without self signed certificates developers would be unable to test locally.

## poetry/add-dev

Provides a wrapper around Poetry's package management system, allowing the user to add development dependencies. It executes the `poetry add --group dev` command with the specified package. This script can be used to add new development tools, test libraries, or other dependencies that are only needed during development and not in production environments.

## poetry/add

Wraps Poetry's package management system, allowing the user to add main, i.e. non-development, dependencies to the project. It executes the `poetry add` command with the specified package name.

## poetry/sync-dev

Configures and synchronises the Poetry development environment by ensuring that the correct Python interpreter is used, updating the lock file, and synchronising all dependencies. It also generates VSCode configuration settings if a `.vscode` directory exists, adding the Poetry virtual environment to its Python path and setting its default interpreter.

## poetry/up

Updates all dependencies in the Poetry environment to their latest versions according to the specified constraints. It first ensures the correct Python interpreter is being used, and then executes `poetry update` to refresh all packages.

## poetry/build

Verifies that the application can be successfully containerised by building Docker images using both Alpine and Ubuntu base images. It runs the Docker build process with the tag `tooling-trusted-release` for each Dockerfile, ensuring that the application builds correctly across different Linux distributions.

## poetry/run

Executes commands within the Poetry managed virtual environment by passing all provided arguments to the `poetry run` command. This allows developers to run any command or script in the context of the project's virtual environment without having to activate it manually, providing a consistent execution context regardless of the developer's system setup. When committing to the project, for example, it is necessary to run `git commit` as `poetry run git commit` in order to use consistent pre-commit hook dependencies.

## poetry/sync

Configures and synchronises the main Poetry dependencies, only, for production environments. It ensures that the correct Python interpreter is used, updates the lock file, and then synchronises the main dependencies, without development packages, using `poetry sync --only main`. This results in a smaller environment, suitable for production deployments.

## build

Builds a Docker container for the application using an Alpine Linux base image, and configures it to listen on port `4443` across all network interfaces (`0.0.0.0`). The resulting image is tagged as `tooling-trusted-release`.

## run

Runs the application, configured for production use, in a Docker container. It launches a detached container that removes itself when stopped, mounts a state directory from the host system to persist data, and uses host networking to simplify port access.
