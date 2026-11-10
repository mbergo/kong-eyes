#!/usr/bin/env bash
# Konnect hybrid: upload the observer schemas to a Control Plane so plugin instances can be created
# (UI, Konnect API or deck). Data planes still need the Lua files installed (kong/Dockerfile).
#   KONNECT_TOKEN=... KONNECT_CP_ID=... [KONNECT_API=https://us.api.konghq.com] scripts/konnect-upload-schema.sh
# Endpoint: POST /v2/control-planes/{cp}/core-entities/plugin-schemas  {"lua_schema": "<schema.lua contents>"}
# Streaming custom plugins (deck custom_plugins) need Gateway 3.15+, so they are not used for 3.10.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${KONNECT_TOKEN:?}"; : "${KONNECT_CP_ID:?}"; API="${KONNECT_API:-https://us.api.konghq.com}"
for p in guardrail-observer guardrail-observer-tail; do
  BODY=$(python3 -c 'import json,sys; print(json.dumps({"lua_schema": open(sys.argv[1]).read()}))' "kong/plugins/$p/schema.lua")
  code=$(curl -sS -o /tmp/konnect-$p.json -w '%{http_code}' -X POST "$API/v2/control-planes/$KONNECT_CP_ID/core-entities/plugin-schemas" \
        -H "Authorization: Bearer $KONNECT_TOKEN" -H 'Content-Type: application/json' -d "$BODY")
  if [[ "$code" == 409 ]]; then
    code=$(curl -sS -o /tmp/konnect-$p.json -w '%{http_code}' -X PUT "$API/v2/control-planes/$KONNECT_CP_ID/core-entities/plugin-schemas/$p" \
        -H "Authorization: Bearer $KONNECT_TOKEN" -H 'Content-Type: application/json' -d "$BODY")
  fi
  echo "$p -> HTTP $code"; head -c 300 /tmp/konnect-$p.json; echo
done
echo "Now install the plugin files on every data plane (kong/Dockerfile) and create instances with deck (deploy/konnect/observer.deck.yaml) or the UI."
