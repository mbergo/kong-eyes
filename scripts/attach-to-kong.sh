#!/usr/bin/env bash
# Attach the observer to ONE route of an EXISTING Kong Gateway (self-managed, DB-backed) via the Admin API.
# Dry-run by default: prints what it verified and the exact payloads. Add --apply to create/update.
# Idempotent: plugin instances are addressed by instance_name (PUT), so re-running updates in place.
#
#   KONG_ADMIN_URL=https://kong-admin.internal:8001 [KONG_ADMIN_TOKEN=...] \
#   EVALUATOR_INGEST_URL=https://evaluator.internal/ingest/kong INGEST_TOKEN=... RUNNER_SECRET=... \
#   scripts/attach-to-kong.sh --route <route name or id> [--guardrails name:priority,...] [--timeouts name:ms,...]
#                             [--environment prod] [--policy-version v3] [--apply]
#
# --guardrails lists YOUR guardrail plugins on the route with their PRIORITY (and ai-proxy:770 if it sits
# between them). The matching gro-probe-<n> plugins are attached between them so the dashboard can show
# per-guardrail latency, who blocked, and suspected fail-opens. Generate and install them first with
# scripts/gen-probes.sh using the same list. --timeouts gives each guardrail's timeout for the fail-open check.
#
# What it refuses to do: touch existing http-log/other logger instances (never diverts an audit
# destination), enable anything globally, or change existing guardrail plugins.
# Prerequisite: the plugin files are installed on EVERY data plane image and KONG_PLUGINS lists
# guardrail-observer (and guardrail-observer-tail). This script verifies that via /.
set -euo pipefail
ROUTE=""; APPLY=0; GUARDS=""; TIMEOUTS=""; ENVIRONMENT="${ENVIRONMENT:-prod}"; POLICY_VERSION="${POLICY_VERSION:-}"; CAPTURE="${CAPTURE_BODY_MODE:-hash}"
while [[ $# -gt 0 ]]; do case "$1" in
  --route) ROUTE="$2"; shift 2;; --guardrails) GUARDS="$2"; shift 2;; --timeouts) TIMEOUTS="$2"; shift 2;; --apply) APPLY=1; shift;; --environment) ENVIRONMENT="$2"; shift 2;;
  --policy-version) POLICY_VERSION="$2"; shift 2;; --capture) CAPTURE="$2"; shift 2;;
  -h|--help) sed -n '2,21p' "$0"; exit 0;; *) echo "unknown arg $1" >&2; exit 2;; esac; done
: "${KONG_ADMIN_URL:?set KONG_ADMIN_URL}"; : "${EVALUATOR_INGEST_URL:?set EVALUATOR_INGEST_URL (http(s)://host/ingest/kong)}"
: "${INGEST_TOKEN:?set INGEST_TOKEN}"; : "${RUNNER_SECRET:?set RUNNER_SECRET}"; [[ -n "$ROUTE" ]] || { echo "--route required" >&2; exit 2; }
AUTH=(); [[ -n "${KONG_ADMIN_TOKEN:-}" ]] && AUTH=(-H "Kong-Admin-Token: $KONG_ADMIN_TOKEN")
ok()  { printf '  \033[1;32m[ok]\033[0m %s\n' "$*"; }; bad() { printf '  \033[1;31m[!!]\033[0m %s\n' "$*"; exit 1; }; note() { printf '  \033[1;33m[..]\033[0m %s\n' "$*"; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }
api() { curl -sS --fail-with-body "${AUTH[@]}" "$@"; }

echo "== 1. gateway identity"
INFO=$(api "$KONG_ADMIN_URL/") || bad "admin API unreachable"
echo "$INFO" | python3 -c 'import sys,json; d=json.load(sys.stdin); c=d["configuration"]; print("  version=%s edition=%s database=%s role=%s" % (d["version"], d.get("edition","community"), c.get("database"), c.get("role","traditional")))'
echo "$INFO" | j 'import sys; v=d["version"].split("."); sys.exit(0 if (int(v[0]),int(v[1]))==(3,10) else 1)' && ok "Kong 3.10.x: internal-ctx adapters verified for this line" || note "not 3.10.x: observer runs, but ai-prompt-guard ctx adapter will report unknown until re-verified (docs/adapters.md)"
echo "$INFO" | j 'import sys; sys.exit(0 if "guardrail-observer" in d["plugins"]["available_on_server"] else 1)' && ok "guardrail-observer loaded (KONG_PLUGINS)" || bad "guardrail-observer NOT in plugins.available_on_server: install the plugin files on every node and add it to KONG_PLUGINS first (see README > Install on an existing Kong)"
echo "$INFO" | j 'import sys; sys.exit(0 if "guardrail-observer-tail" in d["plugins"]["available_on_server"] else 1)' && TAIL=1 && ok "guardrail-observer-tail loaded" || { TAIL=0; note "guardrail-observer-tail not loaded: post-transform snapshot will be missing (optional)"; }
echo "$INFO" | j 'import sys; sys.exit(0 if d["configuration"].get("request_debug", True) else 1)' && ok "request_debug enabled (phase trace available to the runner with the token)" || note "request_debug off: exit attribution falls back to the AI filter chain"
echo "$INFO" | j 'import sys; sys.exit(0 if d["configuration"].get("role","traditional")!="control_plane" else 1)' || note "this is a CONTROL PLANE: the plugin must also be installed on every data plane image"

# middle probes: same placement rule as scripts/gen-probes.sh (one per gap, one below the lowest)
PROBES=$(python3 -c '
import sys
spec = [e for e in sys.argv[1].split(",") if e.strip()]
pr = sorted({int(e.split(":")[1]) for e in spec}, reverse=True)
out = []
for i, hi in enumerate(pr):
    lo = pr[i + 1] if i + 1 < len(pr) else max(hi - 20, 5)
    if hi - lo >= 2: out.append((hi + lo) // 2)
print(" ".join("gro-probe-%d" % p for p in out))' "$GUARDS")
if [[ -n "$GUARDS" ]]; then
  for pn in $PROBES; do
    echo "$INFO" | PN="$pn" j 'import sys,os; sys.exit(0 if os.environ["PN"] in d["plugins"]["available_on_server"] else 1)' && ok "$pn loaded" \
      || bad "$pn is not loaded on this gateway. Run: scripts/gen-probes.sh --guardrails $GUARDS   then rebuild the image and add the printed names to KONG_PLUGINS"
  done
else
  note "no --guardrails given: only the head and tail are attached (no per-guardrail latency or block attribution on ordinary traffic)"
fi

echo "== 2. route and existing plugins"
R=$(api "$KONG_ADMIN_URL/routes/$ROUTE") || bad "route $ROUTE not found"
RID=$(echo "$R" | j 'print(d["id"])'); SID=$(echo "$R" | j 'print((d.get("service") or {}).get("id") or "")')
echo "$R" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("  route id=%s name=%s paths=%s protocols=%s" % (d["id"], d.get("name"), d.get("paths"), d.get("protocols")))'
RP=$(api "$KONG_ADMIN_URL/routes/$RID/plugins"); SP=$([[ -n "$SID" ]] && api "$KONG_ADMIN_URL/services/$SID/plugins" || echo '{"data":[]}'); GP=$(api "$KONG_ADMIN_URL/plugins?size=1000")
python3 - "$RP" "$SP" "$GP" "$RID" "$SID" <<'EOF'
import json, sys
rp, sp, gp = (json.loads(x)["data"] for x in sys.argv[1:4]); rid, sid = sys.argv[4], sys.argv[5]
globals_ = [p for p in gp if not p.get("route") and not p.get("service") and not p.get("consumer")]
def show(label, ps):
    print(f"  {label}: " + (", ".join(f"{p['name']}{'[off]' if not p.get('enabled', True) else ''}" for p in sorted(ps, key=lambda p: p['name'])) or "none"))
show("route-scoped", rp); show("service-scoped", sp); show("global", globals_)
loggers = {"http-log", "file-log", "tcp-log", "udp-log", "syslog", "loggly", "datadog", "opentelemetry", "kafka-log", "splunk"}
existing = [p for p in rp + sp + globals_ if p["name"] in loggers]
if existing:
    print("  existing loggers (NOT touched): " + ", ".join(f"{p['name']}@{'route' if p.get('route') else 'service' if p.get('service') else 'global'}" for p in existing))
    if any(p["name"] == "http-log" and p.get("route") for p in rp):
        print("  !! an http-log already exists on this ROUTE. Kong runs one instance per plugin name per scope precedence;")
        print("     adding a second route-scoped http-log is not possible. Options: (a) point the existing one at the evaluator")
        print("     and have the evaluator forward a copy (EVALUATOR_FORWARD_URL), or (b) add the observer only and ship evidence")
        print("     from the existing collector. This script will NOT modify it.")
guards = [p["name"] for p in rp + sp + globals_ if p["name"].startswith("ai-")]
print("  AI plugins in scope: " + (", ".join(sorted(set(guards))) or "none (is this really an AI route?)"))
EOF
HAS_ROUTE_HTTPLOG=$(echo "$RP" | j 'print(1 if any(p["name"]=="http-log" for p in d["data"]) else 0)')

echo "== 3. payloads"
INGEST_WITH_AUTH=$(python3 -c "
import sys,urllib.parse as u; p=u.urlsplit(sys.argv[1]); netloc=f'kong:{sys.argv[2]}@{p.hostname}'+(f':{p.port}' if p.port else ''); print(u.urlunsplit((p.scheme,netloc,p.path,p.query,'')))" "$EVALUATOR_INGEST_URL" "$INGEST_TOKEN")
OBS=$(python3 -c "
import json,sys
print(json.dumps({'name':'guardrail-observer','instance_name':'guardrail-observer-'+sys.argv[1][:8],'route':{'id':sys.argv[1]},'config':{
 'environment':sys.argv[2],'policy_version':sys.argv[3] or None,'runner_shared_secret':sys.argv[4],'capture_body_mode':sys.argv[5],
 'probe_trail':True,
 'guardrail_plugins':[e.split(':')[0] for e in sys.argv[6].split(',') if e.strip() and e.split(':')[0]!='ai-proxy'],
 'guardrail_timeouts':({e.split(':')[0]:int(e.split(':')[1]) for e in sys.argv[7].split(',') if e.strip()} or None)}}, indent=2))" "$RID" "$ENVIRONMENT" "$POLICY_VERSION" "$RUNNER_SECRET" "$CAPTURE" "$GUARDS" "$TIMEOUTS")
TAILP=$(python3 -c "import json,sys; print(json.dumps({'name':'guardrail-observer-tail','instance_name':'guardrail-observer-tail-'+sys.argv[1][:8],'route':{'id':sys.argv[1]},'config':{'capture_body_mode':sys.argv[2]}}, indent=2))" "$RID" "$CAPTURE")
HL=$(python3 -c "
import json,sys
print(json.dumps({'name':'http-log','instance_name':'guardrail-observer-log-'+sys.argv[1][:8],'route':{'id':sys.argv[1]},'config':{
 'http_endpoint':sys.argv[2],'method':'POST','content_type':'application/json','timeout':5000,'keepalive':60000,
 'queue':{'max_batch_size':50,'max_coalescing_delay':1,'max_entries':10000,'max_retry_time':120,'initial_retry_delay':0.5,'max_retry_delay':10}}}, indent=2))" "$RID" "$INGEST_WITH_AUTH")
echo "$OBS" | sed "s|$RUNNER_SECRET|<RUNNER_SECRET>|"; [[ $TAIL -eq 1 ]] && echo "$TAILP"
for pn in $PROBES; do echo "{ \"name\": \"$pn\", \"instance_name\": \"$pn-${RID:0:8}\", \"route\": { \"id\": \"$RID\" } }"; done
[[ "$HAS_ROUTE_HTTPLOG" == 1 ]] && note "skipping http-log payload (route already has one)" || echo "$HL" | sed "s|$INGEST_TOKEN|<INGEST_TOKEN>|"
echo "  (production tip: replace secret literals with vault references, e.g. {vault://aws/guardrail-observer/runner-secret} and {vault://env/go-ingest-endpoint})"

[[ $APPLY -eq 1 ]] || { echo; note "dry run. Re-run with --apply to create/update these instances on route $ROUTE."; exit 0; }
echo "== 4. apply (PUT by instance_name, idempotent)"
put() { local name="$1" body="$2"; api -X PUT "$KONG_ADMIN_URL/plugins/$name" -H 'Content-Type: application/json' -d "$body" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("  %s id=%s enabled=%s" % (d["name"], d["id"], d["enabled"]))'; }
put "guardrail-observer-${RID:0:8}" "$OBS"
[[ $TAIL -eq 1 ]] && put "guardrail-observer-tail-${RID:0:8}" "$TAILP"
for pn in $PROBES; do put "$pn-${RID:0:8}" "{\"name\":\"$pn\",\"instance_name\":\"$pn-${RID:0:8}\",\"route\":{\"id\":\"$RID\"}}"; done
[[ "$HAS_ROUTE_HTTPLOG" == 1 ]] || put "guardrail-observer-log-${RID:0:8}" "$HL"
ok "attached. Rollback: scripts/rollback.sh --route $ROUTE"
echo "  next: run the suite against this route with KONG_URL=<proxy url> and verify evidence in the evaluator (/doctor?route=$ROUTE)"
