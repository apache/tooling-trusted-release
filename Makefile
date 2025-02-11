.PHONY: build certs check report run sync

MANAGER ?= poetry
PYTHON ?= /usr/bin/python3
SCRIPTS ?= scripts/$(MANAGER)

build:
	$(SCRIPTS)/build

certs:
	$(SCRIPTS)/run scripts/generate-certificates

check:
	$(SCRIPTS)/run pre-commit run --all-files

report:
	@echo SCRIPTS = $(SCRIPTS)

serve:
	$(SCRIPTS)/run hypercorn --bind 127.0.0.1:8080 --keyfile key.pem --certfile cert.pem atr:app

sync:
	$(SCRIPTS)/sync $(PYTHON)
