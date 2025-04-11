.PHONY: build build-alpine build-playwright build-ubuntu certs check \
  docs generate-version obvfix report run run-dev run-playwright \
  run-staging stop serve sync sync-dev

BIND ?= 127.0.0.1:8080
IMAGE ?= tooling-trusted-release
PYTHON ?= $(which python3)
SCRIPTS ?= scripts/poetry

GET_VERSION = $($(SCRIPTS)/run python atr/metadata.py)

build: build-alpine

build-alpine:
	$(SCRIPTS)/build Dockerfile.alpine $(IMAGE)

build-playwright:
	docker build -t atr-playwright -f tests/Dockerfile.playwright tests/playwright

build-ubuntu:
	$(SCRIPTS)/build Dockerfile.ubuntu $(IMAGE)

certs:
	if test ! -f state/cert.pem || test ! -f state/key.pem; \
	then $(SCRIPTS)/run scripts/generate-certificates; \
	fi

check:
	$(SCRIPTS)/run pre-commit run --all-files

docs:
	for fn in docs/*.md; \
	do cmark "$$fn" > "$${fn%.md}.html"; \
	done

generate-version:
	@rm -f atr/_version.py
	@$(SCRIPTS)/run python atr/metadata.py > /tmp/_version.py
	@mv /tmp/_version.py atr/_version.py
	@cat atr/_version.py

obvfix:
	git add -A
	make check || make check
	git commit
	git pull
	git push

report:
	@echo SCRIPTS = $(SCRIPTS)

run: run-dev

run-dev:
	BIND=127.0.0.1:4443 scripts/run

run-playwright:
	docker run --net=host -it atr-playwright

run-staging:
	BIND=127.0.0.1:8443 scripts/run

serve:
	SSH_HOST=127.0.0.1 $(SCRIPTS)/run hypercorn --bind $(BIND) \
		--keyfile key.pem --certfile cert.pem atr.server:app --debug --reload

stop:
	scripts/stop

sync:
	$(SCRIPTS)/sync $(PYTHON)

sync-dev:
	$(SCRIPTS)/sync-dev $(PYTHON)
