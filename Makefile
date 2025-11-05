.PHONY: build build-alpine build-playwright build-ts build-ubuntu certs \
  check check-extra check-light commit docs generate-version ipython \
  manual run-alpine run-playwright run-playwright-slow serve serve-local \
  sync sync-all update-deps help

BIND ?= 127.0.0.1:8080
IMAGE ?= tooling-trusted-release

# ==============================================================================
# Build Targets 🏗️
# ==============================================================================

build: build-alpine ## Default build target (build-alpine).

build-alpine: ## Build the application using Dockerfile.alpine.
	scripts/build Dockerfile.alpine $(IMAGE)

build-playwright: ## Build the Playwright Docker image.
	docker build -t atr-playwright -f tests/Dockerfile.playwright playwright

build-ts: ## Compile TypeScript files.
	tsc -p tsconfig.json

build-ubuntu: ## Build the application using Dockerfile.ubuntu.
	scripts/build Dockerfile.ubuntu $(IMAGE)

# ==============================================================================
# Certificate Targets 🔒
# ==============================================================================

certs: ## Generate self-signed certificates if they don't exist.
	if test ! -f state/cert.pem || test ! -f state/key.pem; \
	then uv run scripts/generate-certificates; \
	fi

certs-local: ## Generate localhost certificates using mkcert (requires mkcert).
	cd state && mkcert localhost.apache.org localhost 127.0.0.1 ::1

# ==============================================================================
# Check & Quality Targets ✅
# ==============================================================================

check: ## Run all pre-commit checks.
	git add -A
	uv run pre-commit run --all-files

check-extra: ## Run extra custom checks (interface order/privacy).
	@git add -A
	@find atr -name '*.py' -exec python3 scripts/interface_order.py {} --quiet \;
	@find atr -name '*.py' -exec python3 scripts/interface_privacy.py {} --quiet \;

check-light: ## Run the light set of pre-commit checks.
	git add -A
	uv run pre-commit run --all-files --config .pre-commit-light.yaml

commit: ## Stage, commit, pull, and push changes.
	git add -A
	git commit
	git pull
	git push

# ==============================================================================
# Documentation Targets 📝
# ==============================================================================

docs: ## Build and check documentation.
	uv run python3 scripts/docs_check.py
	rm -f atr/docs/*.html
	uv run python3 scripts/docs_build.py
	for fn in atr/docs/*.md; \
	do \
	  cmark "$$fn" > "$${fn%.md}.html"; \
	done
	uv run python3 scripts/docs_post_process.py atr/docs/*.html
	uv run python3 scripts/docs_check.py

# ==============================================================================
# Utility & Environment Targets ⚙️
# ==============================================================================

generate-version: ## Generate the version file (atr/version.py).
	@rm -f atr/version.py
	@uv run python3 atr/metadata.py > /tmp/version.py
	@mv /tmp/version.py atr/version.py
	@cat atr/version.py

ipython: ## Start an IPython shell with project dependencies loaded.
	uv run --frozen --with ipython ipython

# ==============================================================================
# Run & Serve Targets 🚀
# ==============================================================================

run-alpine: ## Run the application inside the tooling-trusted-release Alpine Docker image.
	docker run --rm --init --user "$$(id -u):$$(id -g)" \
	  -p 8080:8080 -p 2222:2222 \
	  -v "$$PWD/state:/opt/atr/state" \
	  -v "$$PWD/state/localhost.apache.org+3-key.pem:/opt/atr/state/key.pem" \
	  -v "$$PWD/state/localhost.apache.org+3.pem:/opt/atr/state/cert.pem" \
	  -e APP_HOST=localhost.apache.org:8080 -e SECRET_KEY=insecure-local-key \
	  -e ALLOW_TESTS=1 -e SSH_HOST=0.0.0.0 -e BIND=0.0.0.0:8080 \
	  tooling-trusted-release

run-playwright: ## Run Playwright tests, skipping slow ones.
	docker run --net=host -it atr-playwright python3 test.py --skip-slow

run-playwright-slow: ## Run all Playwright tests.
	docker run --net=host -it atr-playwright python3 test.py --tidy

serve: ## Serve the application using hypercorn with debugging and hot-reloading.
	SSH_HOST=127.0.0.1 uv run hypercorn --bind $(BIND) \
	  --keyfile localhost.apache.org+3-key.pem --certfile localhost.apache.org+3.pem \
	  atr.server:app --debug --reload

serve-local: ## Serve the application locally with full test/debug settings.
	APP_HOST=localhost.apache.org:8080 SECRET_KEY=insecure-local-key \
	  ALLOW_TESTS=1 SSH_HOST=127.0.0.1 uv run hypercorn --bind $(BIND) \
	  --keyfile localhost.apache.org+3-key.pem --certfile localhost.apache.org+3.pem \
	  atr.server:app --debug --reload

# ==============================================================================
# Dependency Targets 📦
# ==============================================================================

sync: ## Sync non-development dependencies using uv.
	uv sync --no-dev

sync-all: ## Sync all dependencies (including development) using uv.
	uv sync --all-groups

update-deps: ## Update pre-commit hooks and dependency locks.
	pre-commit autoupdate || :
	uv lock --upgrade
	uv sync --all-groups

# ==============================================================================
# Help Target 📖
# ==============================================================================

help: ## Display this help message.
	@echo "Available targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'
