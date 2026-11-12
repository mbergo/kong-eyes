#!/usr/bin/env bash
# One-command local setup: choose a destination, generate validated config, start the stack,
# run a synthetic smoke test and print the stage-by-stage doctor report.
#
#   scripts/setup.sh --destination none|grafana|splunk|both     (none: only the collector and its own dashboard)
#   scripts/setup.sh --destination grafana|splunk|both [--with-splunk-stub] [--no-start] [--route NAME]
#
# Idempotent: re-running keeps existing secrets in .env, regenerates derived files, restarts changed services.
# Secrets come from the environment or .env; nothing is written into source files.
set -euo pipefail
export NO_PROXY="localhost,127.0.0.1,${NO_PROXY:-}" no_proxy="localhost,127.0.0.1,${no_proxy:-}"
cd "$(dirname "$0")/.."

DESTINATION=""; START=1; WITH_STUB=0; ROUTE="${ROUTE:-ai-prompt-guard-route}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --destination) DESTINATION="$2"; shift 2;;
    --with-splunk-stub) WITH_STUB=1; shift;;
    --no-start) START=0; shift;;
    --route) ROUTE="$2"; shift 2;;
    -h|--help) sed -n '2,10p' "$0"; exit 0;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac
done
[[ "$DESTINATION" =~ ^(none|grafana|splunk|both)$ ]] || { echo "--destination must be none|grafana|splunk|both" >&2; exit 2; }

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()  { printf '  \033[1;32m[ok]\033[0m %s\n' "$*"; }
bad() { printf '  \033[1;31m[!!]\033[0m %s\n' "$*"; }
need() { command -v "$1" >/dev/null || { bad "missing $1"; exit 1; }; }
need docker; docker compose version >/dev/null 2>&1 || { bad "docker compose v2 required"; exit 1; }
rand() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# ------------------------------------------------------------------ .env
say "Preparing .env (existing values are preserved)"
touch .env
getenv() { grep -E "^$1=" .env | tail -1 | cut -d= -f2- || true; }
setenv() { if grep -qE "^$1=" .env; then sed -i.bak "s|^$1=.*|$1=$2|" .env && rm -f .env.bak; else echo "$1=$2" >> .env; fi; }
[[ -n "$(getenv INGEST_TOKEN)" ]] || setenv INGEST_TOKEN "$(rand)"
[[ -n "$(getenv RUNNER_TOKEN)" ]] || setenv RUNNER_TOKEN "$(rand)"
[[ -n "$(getenv RUNNER_SECRET)" ]] || setenv RUNNER_SECRET "$(rand)"
[[ -n "$(getenv RUNNER_APIKEY)" ]] || setenv RUNNER_APIKEY "runner-$(rand | cut -c1-16)"
[[ -n "$(getenv KONG_REQUEST_DEBUG_TOKEN)" ]] || setenv KONG_REQUEST_DEBUG_TOKEN "$(rand)"
while IFS='=' read -r k v; do [[ -n "$k" && -z "$(getenv "$k")" ]] && setenv "$k" "$v"; done < <(grep -E '^[A-Z_]+_IMAGE=' .env.example)
setenv ENVIRONMENT "$(getenv ENVIRONMENT | grep . || echo local)"
setenv OBSERVED_ROUTE "$ROUTE"

# Kimi: pick up KIMI_API_KEY or MOONSHOT_API_KEY from the shell if not already in .env
KIMI="$(getenv KIMI_API_KEY)"; [[ -n "$KIMI" ]] || KIMI="${KIMI_API_KEY:-${MOONSHOT_API_KEY:-}}"
[[ -z "$KIMI" ]] || setenv KIMI_API_KEY "$KIMI"
if [[ -n "$KIMI" ]]; then
  KB="$(getenv KIMI_BASE_URL)"; [[ -n "$KB" ]] || KB="${KIMI_BASE_URL:-}"
  if [[ -z "$KB" ]]; then
    # Kimi-for-Coding keys (sk-kimi-...) live on api.kimi.com/coding; platform keys (sk-...) on api.moonshot.ai
    [[ "$KIMI" == sk-kimi-* ]] && KB="https://api.kimi.com/coding/v1" || KB="https://api.moonshot.ai/v1"
  fi
  setenv KIMI_BASE_URL "$KB"
  [[ -n "$(getenv KIMI_MODEL)" ]] || setenv KIMI_MODEL "${KIMI_MODEL:-kimi-k3.1-pro}"
fi

# Destinations
PROFILES=""
if [[ "$DESTINATION" == "none" ]]; then setenv OTLP_LOGS_ENDPOINT ""; fi
case "$DESTINATION" in grafana|both)
  PROFILES="grafana"; setenv OTLP_LOGS_ENDPOINT "http://alloy:4318/v1/logs"
  [[ -n "$(getenv LOKI_WRITE_URL)" ]] || setenv LOKI_WRITE_URL "http://loki:3100/otlp"
  [[ -n "$(getenv PROM_REMOTE_WRITE_URL)" ]] || setenv PROM_REMOTE_WRITE_URL "http://prometheus:9090/api/v1/write"
  # Grafana Cloud: derive the Authorization headers Alloy sends (empty for local Loki/Prometheus)
  CT="$(getenv GRAFANA_CLOUD_TOKEN)"
  if [[ -n "$CT" ]]; then
    LU="$(getenv GRAFANA_CLOUD_LOGS_USER)"; MU="$(getenv GRAFANA_CLOUD_METRICS_USER)"
    [[ -n "$LU" ]] && setenv LOKI_AUTH_HEADER "Basic $(printf '%s:%s' "$LU" "$CT" | base64 -w0)"
    [[ -n "$MU" ]] && setenv PROM_AUTH_HEADER "Basic $(printf '%s:%s' "$MU" "$CT" | base64 -w0)"
  else
    setenv LOKI_AUTH_HEADER ""; setenv PROM_AUTH_HEADER ""
  fi;;
esac
case "$DESTINATION" in splunk|both)
  HEC_URL="$(getenv SPLUNK_HEC_URL)"; [[ -n "$HEC_URL" ]] || HEC_URL="${SPLUNK_HEC_URL:-}"
  HEC_TOKEN="$(getenv SPLUNK_HEC_TOKEN)"; [[ -n "$HEC_TOKEN" ]] || HEC_TOKEN="${SPLUNK_HEC_TOKEN:-}"
  if [[ -z "$HEC_URL" || -z "$HEC_TOKEN" ]]; then
    if [[ $WITH_STUB -eq 1 ]]; then
      say "No SPLUNK_HEC_URL/TOKEN: using the local HEC stub (protocol validation only, NOT a live Splunk test)"
      HEC_URL="http://splunk-hec-stub:8088"; HEC_TOKEN="${HEC_TOKEN:-stub-$(rand | cut -c1-12)}"; PROFILES="${PROFILES:+$PROFILES,}splunk-stub"
      setenv SPLUNK_HEC_VERIFY_TLS false
    else
      bad "destination=$DESTINATION needs SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN (env or .env). Add --with-splunk-stub for a local stub."; exit 1
    fi
  fi
  setenv SPLUNK_HEC_URL "$HEC_URL"; setenv SPLUNK_HEC_TOKEN "$HEC_TOKEN"
  [[ -n "$(getenv SPLUNK_HEC_INDEX)" ]] || setenv SPLUNK_HEC_INDEX "${SPLUNK_HEC_INDEX:-}"
  [[ -n "$(getenv SPLUNK_HEC_SOURCETYPE)" ]] || setenv SPLUNK_HEC_SOURCETYPE "kong:guardrail:evaluation";;
esac
# optional corporate CA for pip during builds: copy into the project so BuildKit may read it
CA_SRC="$(getenv BUILD_CA_SOURCE)"; [[ -n "$CA_SRC" ]] || CA_SRC="${BUILD_CA_SOURCE:-}"
if [[ -n "$CA_SRC" && -s "$CA_SRC" ]]; then cp "$CA_SRC" .build/ca.crt; setenv BUILD_CA_FILE "./.build/ca.crt"; setenv BUILD_CA_SOURCE "$CA_SRC"; fi
[[ "$(getenv SPLUNK_HEC_URL)" == *splunk-hec-stub* && "$DESTINATION" != "grafana" ]] && PROFILES="${PROFILES:+$PROFILES,}splunk-stub"
setenv COMPOSE_PROFILES "$PROFILES"
chmod 600 .env
ok ".env ready (profiles: ${PROFILES:-none})"

# ------------------------------------------------------- Kong declarative config
say "Generating kong/declarative/kong.generated.yml"
APIKEY="$(getenv RUNNER_APIKEY)"
# optional service fragments are inserted right under `services:`: the real-provider route, and the
# stand-in guardrail route written by scripts/gen-demo-guards.sh
FRAGS=""; [[ -n "$KIMI" ]] && FRAGS="kong/declarative/kong.kimi.fragment.yml"
[[ -f kong/declarative/kong.demo.fragment.yml ]] && FRAGS="$FRAGS kong/declarative/kong.demo.fragment.yml"
{
  awk -v frags="$FRAGS" '
    { print }
    /^services:$/ && !done { n = split(frags, f, " "); for (i = 1; i <= n; i++) while ((getline l < f[i]) > 0) print l; done=1 }' kong/declarative/kong.yml
} | sed "s|__RUNNER_APIKEY__|$APIKEY|; s|__KIMI_BASE_URL__|$(getenv KIMI_BASE_URL)|g; s|__KIMI_MODEL__|$(getenv KIMI_MODEL)|g" > kong/declarative/kong.generated.yml
ok "kong.generated.yml written$( [[ -n "$KIMI" ]] && echo " (includes /ai/kimi -> $(getenv KIMI_BASE_URL) model $(getenv KIMI_MODEL))" )"

say "Validating declarative config with the pinned Kong image"
set -a; source .env; set +a
docker compose build kong >/dev/null
if docker compose run --rm --no-deps -T --entrypoint "" \
     -e KONG_DATABASE=off -e GO_INGEST_ENDPOINT=http://x -e GO_RUNNER_SECRET=x -e GO_KIMI_AUTH_HEADER=x \
     kong kong config parse /kong/declarative/kong.generated.yml >/tmp/go-parse.log 2>&1; then
  ok "kong config parse: valid"
else
  bad "kong config parse failed:"; cat /tmp/go-parse.log; exit 1
fi

[[ $START -eq 1 ]] || { say "--no-start given; done."; exit 0; }

# -------------------------------------------------------------------- start
say "Starting stack (profiles: $PROFILES)"
docker compose up -d --build --remove-orphans
say "Waiting for Kong and the evaluator"
for i in $(seq 1 60); do
  curl -fsS "http://localhost:${EVALUATOR_PORT:-8800}/health" >/dev/null 2>&1 && curl -fsS "http://localhost:${KONG_ADMIN_PORT:-8001}/status" >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS "http://localhost:${KONG_ADMIN_PORT:-8001}/status" >/dev/null || { bad "Kong did not become healthy"; docker compose logs kong | tail -40; exit 1; }
ok "Kong $(curl -fsS http://localhost:${KONG_ADMIN_PORT:-8001}/ | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("version"), "edition:", d.get("edition"))') up"

# ------------------------------------------------------------ smoke + doctor
if [[ "$DESTINATION" == "none" ]]; then
  ok "no outside destination: everything stays in the collector and shows on its own dashboard"
else
say "Smoke test: synthetic event to every destination"
SMOKE=$(curl -fsS -X POST "http://localhost:${EVALUATOR_PORT:-8800}/smoke?wait_s=20")
echo "$SMOKE" | python3 -c '
import sys,json; d=json.load(sys.stdin); print("  smoke_id:", d["smoke_id"])
for k,v in (d.get("destinations") or {}).items(): print(f"  {k:7s} ->", v["status"], v.get("error") or "")
s = d.get("search") or {}; print("  search (splunk):", s.get("splunk")); print("  search (loki):  ", s.get("loki"))'
say "Doctor"
scripts/doctor.sh || true
fi
echo
say "Next: run the labeled suites"
echo "   make run-suites        # all suites through Kong -> evaluator -> destinations"
echo "   Dashboard: http://localhost:${EVALUATOR_PORT:-8800}/dashboard"
[[ "$DESTINATION" == "none" || "$DESTINATION" == "splunk" ]] || echo "   Grafana: http://localhost:${GRAFANA_PORT:-3000}  dashboard 'Guardrail Observer'"
echo "   Evaluator: http://localhost:${EVALUATOR_PORT:-8800}/runs   /doctor   /metrics"
