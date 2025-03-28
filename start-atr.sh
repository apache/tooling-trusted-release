#!/bin/bash
set -e

# shellcheck source=/dev/null
source .venv/bin/activate

test -d /opt/atr/state || mkdir -p /opt/atr/state

if [ ! -f state/cert.pem ] || [ ! -f state/key.pem ]; then
	python3 scripts/generate-certificates
fi

exec hypercorn --bind "${BIND}" --keyfile key.pem --certfile cert.pem atr.server:app
