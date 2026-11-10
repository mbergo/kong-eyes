#!/usr/bin/env bash
# Build (and optionally push) the Kong data-plane image with the observer plugins installed.
#   scripts/aws/build-image.sh <image:tag> [--base <image@digest>] [--no-fixtures] [--push]
set -euo pipefail
cd "$(dirname "$0")/../.."
IMG="${1:?image:tag required}"; shift
BASE="kong/kong-gateway:3.10.0.19@sha256:a1ce1bc060c1379a5da26db50a2cd1e43db15efbd79b9dff563f18c6e52df282"; FIX=1; PUSH=0
while [[ $# -gt 0 ]]; do case "$1" in --base) BASE="$2"; shift 2;; --no-fixtures) FIX=0; shift;; --push) PUSH=1; shift;; *) echo "unknown $1"; exit 2;; esac; done
docker build --build-arg KONG_BASE_IMAGE="$BASE" --build-arg INSTALL_FIXTURES="$FIX" -t "$IMG" kong/
echo "verifying plugin files + load:"
docker run --rm --entrypoint "" "$IMG" sh -c 'ls /usr/local/share/lua/5.1/kong/plugins | grep -E "guardrail|fixture"; kong version'
docker run --rm -e KONG_DATABASE=off -e KONG_PLUGINS=bundled,guardrail-observer,guardrail-observer-tail --entrypoint "" "$IMG" \
  sh -c 'kong prepare -p /tmp/k 2>&1 | tail -1 && echo "kong prepare ok with KONG_PLUGINS"'
[[ $PUSH -eq 1 ]] && docker push "$IMG"
echo "built $IMG (base $BASE, fixtures=$FIX)"
