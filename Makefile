.PHONY: build build-alpine-ubuntu certs check docs report run serve sync sync-dev

BIND ?= 127.0.0.1:8080
PYTHON ?= $(which python3)
SCRIPTS ?= scripts/poetry

build:
	scripts/build

build-alpine-ubuntu:
	$(SCRIPTS)/build

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

report:
	@echo SCRIPTS = $(SCRIPTS)

run:
	scripts/run

serve:
	$(SCRIPTS)/run hypercorn --bind $(BIND) --keyfile key.pem --certfile cert.pem atr.server:app --debug --reload

sync:
	$(SCRIPTS)/sync $(PYTHON)

sync-dev:
	$(SCRIPTS)/sync-dev $(PYTHON)
