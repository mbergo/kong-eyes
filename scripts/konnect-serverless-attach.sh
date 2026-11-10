#!/usr/bin/env bash
# Attach the SLIM observer (http-log + custom_fields_by_lua) to a Konnect control plane where custom plugins
# are not available (Serverless Gateway). Creates ONE tagged route (/ai/kimi-konnect) + consumer; touches
# nothing else. Reversible: scripts/konnect-serverless-detach.sh (deck --select-tag guardrail-observer).
#
#   DECK_KONNECT_TOKEN=… DECK_KONNECT_ADDR=https://us.api.konghq.com DECK_KONNECT_CONTROL_PLANE_NAME=<cp> \
#   INGEST_PUBLIC_URL=https://<ngrok>.ngrok-free.app KIMI_API_KEY=… scripts/konnect-serverless-attach.sh [--apply]
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] && { set -a; source .env; set +a; }
: "${DECK_KONNECT_TOKEN:?}"; : "${DECK_KONNECT_ADDR:?}"; : "${DECK_KONNECT_CONTROL_PLANE_NAME:?}"
: "${INGEST_PUBLIC_URL:?public https URL that reaches the evaluator (ngrok/cloudflared/ALB)}"; : "${INGEST_TOKEN:?}"; : "${RUNNER_APIKEY:?}"
KIMI="${KIMI_API_KEY:-${MOONSHOT_API_KEY:-}}"; : "${KIMI:?KIMI_API_KEY}"
KB="${KIMI_BASE_URL:-}"; [[ -n "$KB" ]] || { [[ "$KIMI" == sk-kimi-* ]] && KB="https://api.kimi.com/coding/v1" || KB="https://api.moonshot.ai/v1"; }
export DECK_KONNECT_TOKEN DECK_KONNECT_ADDR DECK_KONNECT_CONTROL_PLANE_NAME
OUT=$(mktemp /tmp/konnect-slim.XXXXXX.yaml); trap 'rm -f "$OUT"' EXIT
python3 - "$OUT" "$DECK_KONNECT_CONTROL_PLANE_NAME" "$RUNNER_APIKEY" "$KB" "$KIMI" "${KIMI_MODEL:-kimi-k3.1-pro}" \
  "$(python3 -c "import sys,urllib.parse as u; p=u.urlsplit(sys.argv[1]); print(u.urlunsplit((p.scheme, 'kong:'+sys.argv[2]+'@'+p.netloc, '/ingest/kong','','')))" "$INGEST_PUBLIC_URL" "$INGEST_TOKEN")" <<'EOF'
import sys
out, cp, apikey, kb, kimi, model, ingest = sys.argv[1:]
s = open("deploy/konnect/serverless-slim.deck.yaml.tpl").read()
for k, v in {"__CP_NAME__": cp, "__RUNNER_APIKEY__": apikey, "__KIMI_BASE_URL__": kb, "__KIMI_API_KEY__": kimi, "__KIMI_MODEL__": model, "__INGEST_ENDPOINT__": ingest}.items():
    s = s.replace(k, v)
open(out, "w").write(s)
EOF
echo "== diff (tag guardrail-observer only)"
deck gateway diff "$OUT" --select-tag guardrail-observer 2>&1 | sed "s|$KIMI|<KIMI_API_KEY>|g; s|$INGEST_TOKEN|<INGEST_TOKEN>|g" | tail -25
if [[ "${1:-}" == "--apply" ]]; then
  deck gateway sync "$OUT" --select-tag guardrail-observer 2>&1 | sed "s|$KIMI|<KIMI_API_KEY>|g; s|$INGEST_TOKEN|<INGEST_TOKEN>|g" | tail -5
  echo "applied. Route: <proxy>/ai/kimi-konnect  (consumer guardrail-runner, apikey = RUNNER_APIKEY from .env)"
  echo "NOTE: the Kimi key is stored in the ai-proxy config on Konnect for this test; rotate it afterwards or move it to a Konnect vault."
else
  echo "(dry run; add --apply)"
fi
