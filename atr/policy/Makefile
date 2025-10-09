.PHONY: all clean

all: third-party-licenses.json

third-party-licenses.html: third-party-licenses.md
	cmark third-party-licenses.md > third-party-licenses.html

third-party-licenses.json: third-party-licenses.html
	python3 ../../scripts/extract_spdx_identifiers.py third-party-licenses.html > third-party-licenses.json

clean:
	rm -f third-party-licenses.html third-party-licenses.json
