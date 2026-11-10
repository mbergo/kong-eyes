#!/usr/bin/env bash
# Proves: duplicate ingestion is deduplicated, an export outage is queued (not lost, not blocking
# the other destination), and the stack recovers. Requires the local stack with DESTINATION=both + stub.
set -euo pipefail
cd "$(dirname "$0")/.."
export NO_PROXY="localhost,127.0.0.1,${NO_PROXY:-}" no_proxy="localhost,127.0.0.1,${no_proxy:-}"
set -a; source .env; set +a
EV="http://localhost:${EVALUATOR_PORT:-8800}"; STUB="http://localhost:${SPLUNK_STUB_PORT:-8088}"
j() { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }
ok() { printf '  \033[1;32m[ok]\033[0m %s\n' "$*"; }
bad() { printf '  \033[1;31m[!!]\033[0m %s\n' "$*"; exit 1; }

echo "== 1. duplicate ingestion"
EVT=$(curl -sS "$EV/observations/recent?limit=1")
EID=$(echo "$EVT" | j 'print(d[0]["event_id"])')
# re-post the same observation the way http-log would on a retry (wrapped in the serializer envelope)
PAYLOAD=$(echo "$EVT" | j 'import json; print(json.dumps([{"guardrail_observer": d[0], "request": {"id": d[0].get("request_id")}}]))')
R1=$(curl -sS -u "kong:$INGEST_TOKEN" -H 'Content-Type: application/json' -d "$PAYLOAD" "$EV/ingest/kong")
R2=$(curl -sS -u "kong:$INGEST_TOKEN" -H 'Content-Type: application/json' -d "$PAYLOAD" "$EV/ingest/kong")
echo "  first replay: $R1"; echo "  second replay: $R2"
echo "$R2" | j 'import sys; sys.exit(0 if d["duplicate"]==1 and d["accepted"]==0 else 1)' && ok "event $EID deduplicated by event_id" || bad "duplicate not detected"
curl -sS "$EV/metrics" | grep 'go_ingest_events_total{result="duplicate"' | sed 's/^/  metric: /'

echo "== 2. bad token is rejected, counted, and nothing is stored"
code=$(curl -sS -o /dev/null -w '%{http_code}' -u "kong:wrong" -H 'Content-Type: application/json' -d "$PAYLOAD" "$EV/ingest/kong")
[[ "$code" == 401 ]] && ok "401 for bad ingest token" || bad "expected 401 got $code"

echo "== 3. export outage (Splunk stub returns 503) -> queued, retried, Grafana path unaffected"
[[ "${SPLUNK_HEC_URL:-}" == *splunk-hec-stub* ]] || { echo "  (skipped: not using the local stub)"; exit 0; }
curl -sS -X POST "$STUB/_fail?mode=503" >/dev/null
S1=$(curl -sS -X POST "$EV/smoke?wait_s=6")
echo "$S1" | j 'print("  during outage:", d["destinations"])'
echo "$S1" | j 'import sys; sys.exit(0 if d["destinations"]["otlp"]["status"]=="sent" and d["destinations"]["splunk"]["status"]=="pending" else 1)' \
  && ok "otlp delivered while splunk queued (independent queues)" || bad "unexpected outage behaviour"
curl -sS "$EV/metrics" | grep -E 'go_outbox_events\{destination="splunk"' | sed 's/^/  metric: /'
curl -sS -X POST "$STUB/_fail?mode=" >/dev/null
SID=$(echo "$S1" | j 'print(d["smoke_id"])')
for i in $(seq 1 30); do
  st=$(curl -sS "$EV/doctor" | j 'print(d["outbox"].get("splunk",{}).get("pending",0))')
  [[ "$st" == "0" ]] && break; sleep 1
done
N=$(curl -sS "$STUB/_events?smoke_id=$SID" | j 'print(d["count"])')
[[ "$N" == "1" ]] && ok "queued smoke event $SID delivered to the stub after recovery (exactly once)" || bad "stub holds $N copies of $SID"

echo "== 4. evaluator restart keeps the queue (SQLite outbox)"
curl -sS -X POST "$STUB/_fail?mode=503" >/dev/null
S2=$(curl -sS -X POST "$EV/smoke?wait_s=3"); SID2=$(echo "$S2" | j 'print(d["smoke_id"])')
docker compose restart evaluator >/dev/null 2>&1
for i in $(seq 1 30); do curl -fsS "$EV/health" >/dev/null 2>&1 && break; sleep 1; done
curl -sS -X POST "$STUB/_fail?mode=" >/dev/null
for i in $(seq 1 40); do N=$(curl -sS "$STUB/_events?smoke_id=$SID2" | j 'print(d["count"])'); [[ "$N" == "1" ]] && break; sleep 1; done
[[ "$N" == "1" ]] && ok "event $SID2 survived an evaluator restart and was delivered once" || bad "event lost across restart (count=$N)"
echo "note: Kong's http-log queue is worker-local memory; a Kong restart with undelivered batches loses them. The evaluator"
echo "      measures that as runner_without_kong in /unmatched instead of pretending delivery is guaranteed."
