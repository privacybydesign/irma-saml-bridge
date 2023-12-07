#!/usr/bin/env bash

# This script is included for documentation on how to generate the keys in the dev-keys directory.

set -euo pipefail

pushd ./dev-keys

rm *.crt *.der *.pem

# Creating JWT keys
openssl genrsa -out jwt.pem 2048
openssl pkcs8 -topk8 -inform PEM -outform DER -in jwt.pem -out jwt.der -nocrypt
openssl rsa -in jwt.pem -pubout -outform DER -out jwt.pub.der
openssl rsa -in jwt.pem -pubout -outform PEM -out jwt.pub.pem

# Creating SAML Certificate
openssl req -x509 -newkey rsa:4096 -keyout idp.pem -out ./idp.crt -days 365 -nodes
openssl pkcs8 -topk8 -inform PEM -outform DER -in ./idp.pem -out ./idp.der -nocrypt

# Generate IRMA docker test keys.
../utils/keygen.sh ./irma-test ./irma-test.pub

popd