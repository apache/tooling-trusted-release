#!/bin/sh
# This script requires Alpine Linux
# Usage: sh mk.sh

# Use strict mode in POSIX sh
set -eux

# Add Sequoia to system packages
apk add cmd:sq

# Set the UID for the key pair
_uid='Apache Tooling (For test use only) <apache-tooling@example.invalid>'

# Generate the secret key
sq key generate --userid "$_uid" --rev-cert rev-cert.tmp --shared-key \
  --output tmp.secret.asc --without-password

# Remove the rev cert
rm rev-cert.tmp

# Extract the fingerprint of the secret key
_fp=$(sq inspect tmp.secret.asc | awk '/Fingerprint:/ {print $2}')

# Move the secret key to a file name containing its fingerprint
mv tmp.secret.asc "${_fp}.secret.asc"

# Compute the public key, with a file name containing its fingerprint
sq key delete --cert-file "${_fp}.secret.asc" --output "${_fp}.asc"

# Enter the directory containing the artifact
cd apache-test-0.2/
rm ./*.asc ./*.sha512

# Generate the SHA-2-512 hash
sha512sum apache-test-0.2.tar.gz > \
  apache-test-0.2.tar.gz.sha512

# Generate the signature
sq sign --signer-file "../${_fp}.secret.asc" \
  --signature-file apache-test-0.2.tar.gz.asc \
  apache-test-0.2.tar.gz

# Remove the secret key
rm "../${_fp}.secret.asc"
