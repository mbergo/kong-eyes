#!/usr/bin/env bash
# Stage-by-stage health report. A successful HTTP connection is NOT a successful setup;
# every stage below checks the thing it names.
set -uo pipefail
export NO_PROXY="localhost,127.0.0.1,${NO_PROXY:-}" no_proxy="localhost,127.0.0.1,${no_proxy:-}"
cd "$(dirname "$0")/.."
[[ -f .env ]] && { set -a; source .env; set +a; }
EV="http://localhost:${EVALUATOR_PORT:-8800}"; ADMIN="http://localhost:${KONG_ADMIN_PORT:-8001}"; GF="http://localhost:${GRAFANA_PORT:-3000}"
ROUTE="${OBSERVED_ROUTE:-ai-prompt-guard-route}"
ok()  { printf '  \033[1;32m[ok]\033[0m %-26s %s\n' "$1" "$2"; }
bad() { printf '  \033[1;31m[!!]\033[0m %-26s %s\n' "$1" "$2"; RC=1; }
pend(){ printf '  \033[1;33m[..]\033[0m %-26s %s\n' "$1" "$2"; }
RC=0
j() { python3 -c "import sys,json; d=json.load(sys.stdin); $1" 2>/dev/null; }

# 1 plugin loaded on the gateway
INFO=$(curl -fsS "$ADMIN/" 2>/dev/null)
if [[ -n "$INFO" ]]; then
  if echo "$INFO" | j 'import sys; sys.exit(0 if "guardrail-observer" in d["plugins"]["available_on_server"] else 1)'; then
    ok "plugin_loaded" "guardrail-observer in KONG_PLUGINS on $(echo "$INFO" | j 'print(d["version"], d.get("edition",""))')"
  else bad "plugin_loaded" "guardrail-observer not in plugins.available_on_server"; fi
else bad "plugin_loaded" "Kong admin API unreachable at $ADMIN"; fi

# 2 scope active: observer + a logger on the selected route
RP=$(curl -fsS "$ADMIN/routes/$ROUTE/plugins" 2>/dev/null)
if [[ -n "$RP" ]]; then
  NAMES=$(echo "$RP" | j 'print(",".join(sorted(p["name"] for p in d["data"] if p.get("enabled", True))))')
  [[ "$NAMES" == *guardrail-observer* ]] && ok "scope_active" "route=$ROUTE plugins=[$NAMES]" || bad "scope_active" "observer not attached to $ROUTE ([$NAMES])"
  [[ "$NAMES" == *http-log* ]] || bad "logger_present" "no http-log on $ROUTE: evidence cannot leave Kong"
else bad "scope_active" "route $ROUTE not found"; fi

# 3-4 evidence received & labels joined (evaluator view)
DOC=$(curl -fsS "$EV/doctor?route=$ROUTE" 2>/dev/null)
if [[ -n "$DOC" ]]; then
  echo "$DOC" | j '
s=d["stages"]
def line(k,o,detail):
    tag={True:"\033[1;32m[ok]\033[0m",False:"\033[1;31m[!!]\033[0m",None:"\033[1;33m[..]\033[0m"}[o]
    print(f"  {tag} {k:<26} {detail}")
line("evidence_received", s["evidence_received"]["ok"], f"last guardrails={s['evidence_received']['detail']} gaps={s['evidence_received']['gaps']}" if s["evidence_received"]["ok"] else "no observation with a guardrail verdict yet (run a suite)")
line("labels_joined", s["labels_joined"]["ok"], str(s["labels_joined"]["detail"][:3]))
da=s["destination_accepted"]
if "ok" in da and da.get("ok") is False and "detail" in da and isinstance(da["detail"],str): line("destination_accepted", False, da["detail"])
else:
    for dest,v in da.items(): line(f"destination_accepted:{dest}", v["ok"], v["detail"])
print(f"       ingest={d['ingest']} outbox={d['outbox']}")'
else bad "evaluator" "unreachable at $EV"; fi

# 6 dashboard query verified
if [[ -n "${OTLP_LOGS_ENDPOINT:-}" ]]; then
  if curl -fsS -u "${GRAFANA_ADMIN_USER:-admin}:${GRAFANA_ADMIN_PASSWORD:-admin}" "$GF/api/dashboards/uid/guardrail-observer" >/dev/null 2>&1; then
    Q=$(curl -fsS -u "${GRAFANA_ADMIN_USER:-admin}:${GRAFANA_ADMIN_PASSWORD:-admin}" -G "$GF/api/datasources/proxy/uid/go-loki/loki/api/v1/query" \
         --data-urlencode 'query=sum(count_over_time({service_name="guardrail-evaluator"}[24h]))' 2>/dev/null | j 'print(d["data"]["result"][0]["value"][1] if d["data"]["result"] else 0)')
    P=$(curl -fsS -u "${GRAFANA_ADMIN_USER:-admin}:${GRAFANA_ADMIN_PASSWORD:-admin}" -G "$GF/api/datasources/proxy/uid/go-prom/api/v1/query" --data-urlencode 'query=count(go_eval_units)' 2>/dev/null | j 'print(d["data"]["result"][0]["value"][1] if d["data"]["result"] else 0)')
    if [[ "${Q:-0}" != "0" ]]; then ok "dashboard_query_verified:grafana" "dashboard provisioned; Loki has ${Q} evaluator events; Prometheus go_eval_units series=${P:-0}"
    else pend "dashboard_query_verified:grafana" "dashboard provisioned but Loki returned 0 evaluator events (run a suite / check alloy logs)"; fi
  else bad "dashboard_query_verified:grafana" "dashboard uid guardrail-observer not found at $GF"; fi
fi
if [[ -n "${SPLUNK_HEC_URL:-}" ]]; then
  if [[ "$SPLUNK_HEC_URL" == *splunk-hec-stub* ]]; then
    N=$(curl -fsS "http://localhost:${SPLUNK_STUB_PORT:-8088}/_stats" 2>/dev/null | j 'print(d["events"])')
    ok "destination_received:splunk-stub" "stub holds ${N:-0} events (protocol validated; NOT a live Splunk test)"
    pend "dashboard_query_verified:splunk" "pending: needs a real Splunk with search access (set SPLUNK_SEARCH_URL/SPLUNK_SEARCH_TOKEN and run scripts/splunk-verify.sh)"
  elif [[ -n "${SPLUNK_SEARCH_URL:-}" && -n "${SPLUNK_SEARCH_TOKEN:-}" ]]; then
    scripts/splunk-verify.sh || RC=1
  else
    pend "dashboard_query_verified:splunk" "delivery accepted by HEC; search verification pending (set SPLUNK_SEARCH_URL + SPLUNK_SEARCH_TOKEN)"
  fi
fi
exit $RC
