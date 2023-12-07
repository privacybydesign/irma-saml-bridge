#!/usr/bin/env bash

set -euo pipefail

pushd './assets'
./build.sh
popd

# The version number can be found in the most recent Git tag
export VERSION=`git describe --tags --abbrev=0`
export BUILD_TYPE="${BUILD_TYPE:-devel}"
export BUILD_NUMBER="${BUILD_NUMBER:-1}"

mvn package

rm -rf ./artifacts
mkdir -p ./artifacts
cp target/IRMA-saml-bridge-${VERSION}.${BUILD_TYPE}${BUILD_NUMBER}.jar ./artifacts/irma-saml-bridge.jar