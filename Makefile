.PHONY: build build-alpine build-playwright build-ubuntu certs check \
  docs generate-version obvfix report run run-dev run-playwright \
  run-playwright-slow run-staging stop serve serve-local sync sync-dev

BIND ?= 127.0.0.1:8080
IMAGE ?= tooling-trusted-release
PYTHON ?= $(which python3)
SCRIPTS ?= scripts/poetry

GET_VERSION = $($(SCRIPTS)/run python atr/metadata.py)

build: build-alpine

build-alpine:
	$(SCRIPTS)/build Dockerfile.alpine $(IMAGE)

build-playwright:
	docker build -t atr-playwright -f tests/Dockerfile.playwright playwright

build-ubuntu:
	$(SCRIPTS)/build Dockerfile.ubuntu $(IMAGE)

certs:
	if test ! -f state/cert.pem || test ! -f state/key.pem; \
	then $(SCRIPTS)/run scripts/generate-certificates; \
	fi

check:
	$(SCRIPTS)/run pre-commit run --all-files

check-extra:
	@find atr -name '*.py' -exec python3 scripts/interface_order.py {} --quiet \;
	@find atr -name '*.py' -exec python3 scripts/interface_privacy.py {} --quiet \;

docs:
	for fn in docs/*.md; \
	do cmark "$$fn" > "$${fn%.md}.html"; \
	done

generate-version:
	@rm -f atr/version.py
	@$(SCRIPTS)/run python atr/metadata.py > /tmp/version.py
	@mv /tmp/version.py atr/version.py
	@cat atr/version.py

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
	docker run --net=host -it atr-playwright python3 test.py --skip-slow

run-playwright-slow:
	docker run --net=host -it atr-playwright python3 test.py --tidy

run-staging:
	BIND=127.0.0.1:8443 scripts/run

serve:
	SSH_HOST=127.0.0.1 $(SCRIPTS)/run hypercorn --bind $(BIND) \
		--keyfile key.pem --certfile cert.pem atr.server:app --debug --reload

serve-local:
	APP_HOST=127.0.0.1:8080 LOCAL_DEBUG=1 \
		SSH_HOST=127.0.0.1 $(SCRIPTS)/run hypercorn --bind $(BIND) \
		--keyfile key.pem --certfile cert.pem atr.server:app --debug --reload

stop:
	scripts/stop

sync:
	$(SCRIPTS)/sync $(PYTHON)

sync-dev:
	$(SCRIPTS)/sync-dev $(PYTHON)
