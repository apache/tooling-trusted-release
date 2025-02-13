.PHONY: build certs check docs report serve sync

BIND ?= 127.0.0.1:8080
MANAGER ?= poetry
PYTHON ?= $(which python3)
SCRIPTS ?= scripts/$(MANAGER)

build:
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

serve:
	$(SCRIPTS)/run hypercorn --bind $(BIND) --keyfile key.pem --certfile cert.pem atr:app

sync:
	$(SCRIPTS)/sync $(PYTHON)
