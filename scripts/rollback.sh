#!/usr/bin/env bash
# Remove the observer from one route of an existing Kong (Admin API). Leaves guardrails, existing loggers
# and the installed plugin files untouched. Full removal = also drop the names from KONG_PLUGINS and
# rebuild the image (see README > Rollback).
#   KONG_ADMIN_URL=... [KONG_ADMIN_TOKEN=...] scripts/rollback.sh --route <route> [--apply]
set -euo pipefail
ROUTE=""; APPLY=0
while [[ $# -gt 0 ]]; do case "$1" in --route) ROUTE="$2"; shift 2;; --apply) APPLY=1; shift;; *) echo "unknown arg $1" >&2; exit 2;; esac; done
: "${KONG_ADMIN_URL:?}"; [[ -n "$ROUTE" ]] || { echo "--route required" >&2; exit 2; }
AUTH=(); [[ -n "${KONG_ADMIN_TOKEN:-}" ]] && AUTH=(-H "Kong-Admin-Token: $KONG_ADMIN_TOKEN")
RID=$(curl -sS --fail-with-body "${AUTH[@]}" "$KONG_ADMIN_URL/routes/$ROUTE" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
for n in guardrail-observer-${RID:0:8} guardrail-observer-tail-${RID:0:8} guardrail-observer-log-${RID:0:8}; do
  if curl -sS -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$KONG_ADMIN_URL/plugins/$n" | grep -q 200; then
    if [[ $APPLY -eq 1 ]]; then curl -sS --fail-with-body "${AUTH[@]}" -X DELETE "$KONG_ADMIN_URL/plugins/$n" && echo "deleted $n"; else echo "would delete $n"; fi
  else echo "absent $n"; fi
done
[[ $APPLY -eq 1 ]] || echo "(dry run; add --apply)"
