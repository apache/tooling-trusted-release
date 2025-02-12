.PHONY: build certs check docs report serve sync

MANAGER ?= poetry
PYTHON ?= $(which python3)
SCRIPTS ?= scripts/$(MANAGER)

build:
	$(SCRIPTS)/build

certs:
	$(SCRIPTS)/run scripts/generate-certificates

check:
	$(SCRIPTS)/run pre-commit run --all-files

docs:
	for fn in docs/*.md; \
	do cmark "$$fn" > "$${fn%.md}.html"; \
	done

report:
	@echo SCRIPTS = $(SCRIPTS)

serve:
	$(SCRIPTS)/run hypercorn --bind 127.0.0.1:8080 --keyfile key.pem --certfile cert.pem atr:app

sync:
	$(SCRIPTS)/sync $(PYTHON)
