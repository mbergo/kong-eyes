#!/usr/bin/env bash
# Remove everything tagged guardrail-observer from the Konnect control plane (route, service, consumer, plugins).
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] && { set -a; source .env; set +a; }
export DECK_KONNECT_TOKEN DECK_KONNECT_ADDR DECK_KONNECT_CONTROL_PLANE_NAME
printf '_format_version: "3.0"\n_konnect:\n  control_plane_name: %s\n' "$DECK_KONNECT_CONTROL_PLANE_NAME" > /tmp/go-empty.yaml
deck gateway diff /tmp/go-empty.yaml --select-tag guardrail-observer 2>&1 | tail -15
[[ "${1:-}" == "--apply" ]] && deck gateway sync /tmp/go-empty.yaml --select-tag guardrail-observer 2>&1 | tail -3 || echo "(dry run; add --apply)"
