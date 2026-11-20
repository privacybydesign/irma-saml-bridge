#!/bin/sh
# Builds the page's script and style sheet and puts them where the Go
# service embeds them. The Dockerfile does the same in its node stage.
set -eu
cd "$(dirname "$0")"

rm -rf dist
yarn install --frozen-lockfile
yarn run build

find ../static/assets -mindepth 1 ! -name .gitkeep -delete
cp dist/* ../static/assets/
