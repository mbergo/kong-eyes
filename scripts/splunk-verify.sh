#!/usr/bin/env bash
# Verify search visibility of a smoke event in a REAL Splunk (needs read access to the search API).
#   SPLUNK_SEARCH_URL=https://splunk:8089 SPLUNK_SEARCH_TOKEN=<bearer> [SPLUNK_HEC_INDEX=main] scripts/splunk-verify.sh [smoke_id]
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] && { set -a; source .env; set +a; }
: "${SPLUNK_SEARCH_URL:?}"; : "${SPLUNK_SEARCH_TOKEN:?}"
EV="http://localhost:${EVALUATOR_PORT:-8800}"
SID="${1:-}"
if [[ -z "$SID" ]]; then
  SID=$(curl -sS -X POST "$EV/smoke?wait_s=20" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["smoke_id"]); import sys as s; s.stderr.write(str(d["destinations"])+"\n")')
fi
IDX="${SPLUNK_HEC_INDEX:-*}"
Q="search index=$IDX sourcetype=\"${SPLUNK_HEC_SOURCETYPE:-kong:guardrail:evaluation}\" smoke_id=\"$SID\" | head 1"
for i in $(seq 1 12); do
  OUT=$(curl -sSk -H "Authorization: Bearer $SPLUNK_SEARCH_TOKEN" "$SPLUNK_SEARCH_URL/services/search/jobs/export" \
        --data-urlencode "search=$Q" --data-urlencode "output_mode=json" --data-urlencode "earliest_time=-15m")
  if echo "$OUT" | grep -q "$SID"; then printf '  \033[1;32m[ok]\033[0m dashboard_query_verified:splunk  smoke event %s is searchable (%s)\n' "$SID" "$Q"; exit 0; fi
  sleep 5
done
printf '  \033[1;31m[!!]\033[0m dashboard_query_verified:splunk  %s accepted by HEC but not searchable after 60s (index/sourcetype/permissions?)\n' "$SID"; exit 1
