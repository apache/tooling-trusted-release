.PHONY: build build-alpine build-playwright build-ts build-ubuntu certs \
  check check-extra check-light commit docs generate-version run-playwright \
  run-playwright-slow serve serve-local sync update-deps

BIND ?= 127.0.0.1:8080
IMAGE ?= tooling-trusted-release

build: build-alpine

build-alpine:
	scripts/build Dockerfile.alpine $(IMAGE)

build-playwright:
	docker build -t atr-playwright -f tests/Dockerfile.playwright playwright

build-ts:
	tsc -p tsconfig.json

build-ubuntu:
	scripts/build Dockerfile.ubuntu $(IMAGE)

certs:
	if test ! -f state/cert.pem || test ! -f state/key.pem; \
	then uv run scripts/generate-certificates; \
	fi

certs-local:
	mkcert localhost.apache.org localhost 127.0.0.1 ::1

check:
	git add -A
	uv run pre-commit run --all-files

check-extra:
	@git add -A
	@find atr -name '*.py' -exec python3 scripts/interface_order.py {} --quiet \;
	@find atr -name '*.py' -exec python3 scripts/interface_privacy.py {} --quiet \;

check-light:
	git add -A
	uv run pre-commit run --all-files --config .pre-commit-light.yaml

commit:
	git add -A
	git commit
	git pull
	git push

docs:
	for fn in docs/*.md; \
	do \
	  cmark "$$fn" > "$${fn%.md}.html"; \
	done

generate-version:
	@rm -f atr/version.py
	@uv run python atr/metadata.py > /tmp/version.py
	@mv /tmp/version.py atr/version.py
	@cat atr/version.py

run-playwright:
	docker run --net=host -it atr-playwright python3 test.py --skip-slow

run-playwright-slow:
	docker run --net=host -it atr-playwright python3 test.py --tidy

serve:
	SSH_HOST=127.0.0.1 uv run hypercorn --bind $(BIND) \
	  --keyfile localhost.apache.org+3-key.pem --certfile localhost.apache.org+3.pem \
	  atr.server:app --debug --reload

serve-local:
	APP_HOST=localhost.apache.org:8080 LOCAL_DEBUG=1 SECRET_KEY=insecure-local-key \
	  SSH_HOST=127.0.0.1 uv run hypercorn --bind $(BIND) \
	  --keyfile localhost.apache.org+3-key.pem --certfile localhost.apache.org+3.pem \
	  atr.server:app --debug --reload

sync:
	uv sync --no-dev

update-deps:
	uv lock --upgrade
	uv sync --all-groups
