#!/bin/sh
set -eu

cd "$(dirname "$0")"

echo "Building and running ATR integration tests..."
docker compose up --build --abort-on-container-exit --exit-code-from playwright

# Clean up
docker compose down -v
