.PHONY: build build-alpine build-ubuntu certs check docs generate-version report run stop serve sync sync-dev



BIND ?= 127.0.0.1:8080
PYTHON ?= $(which python3)
SCRIPTS ?= scripts/poetry

GET_VERSION = $($(SCRIPTS)/run python atr/metadata.py)

build: build-alpine

build-alpine:
	$(SCRIPTS)/build Dockerfile.alpine

build-ubuntu:
	$(SCRIPTS)/build Dockerfile.ubuntu

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

report:
	@echo SCRIPTS = $(SCRIPTS)

run:
	scripts/run

stop:
	scripts/stop

serve:
	$(SCRIPTS)/run hypercorn --bind $(BIND) --keyfile key.pem --certfile cert.pem atr.server:app --debug --reload

sync:
	$(SCRIPTS)/sync $(PYTHON)

sync-dev:
	$(SCRIPTS)/sync-dev $(PYTHON)
