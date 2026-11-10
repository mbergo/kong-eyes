#!/usr/bin/env bash
# Observer overhead A/B + bounded-memory check.
#   /ai/fixture  (observer + tail enabled)  vs  /ai/baseline (identical route without them)
# Measures client-side latency with N sequential requests per route (same mock model, CLEAN answer),
# and Kong worker RSS before/after a burst of large bodies through the observed route.
# Boundaries: numbers include the mock model and Docker networking; only the DIFFERENCE between
# routes is attributable to the observer plugins. Run on an idle machine; repeat for confidence.
set -euo pipefail
cd "$(dirname "$0")/.."
export NO_PROXY="localhost,127.0.0.1,${NO_PROXY:-}" no_proxy="localhost,127.0.0.1,${no_proxy:-}"
[[ -f .env ]] && { set -a; source .env; set +a; }
N=${N:-200}; KONG="http://localhost:${KONG_PROXY_PORT:-8000}"
BODY='{"model":"mock-gpt","messages":[{"role":"user","content":"perf respond:CLEAN"}]}'

bench() { # route -> prints p50 p95 mean (ms)
  python3 - "$1" "$N" "$KONG" "$RUNNER_APIKEY" "$BODY" <<'EOF'
import sys, time, urllib.request, statistics
route, n, kong, key, body = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5].encode()
lat = []
for i in range(n):
    req = urllib.request.Request(kong + route, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "apikey": key, "Accept-Encoding": "identity"})
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()
    lat.append((time.perf_counter() - t0) * 1000)
lat.sort()
print(f"{lat[len(lat)//2]:.2f} {lat[int(len(lat)*0.95)-1]:.2f} {statistics.mean(lat):.2f}")
EOF
}

echo "warming up"; for r in /ai/baseline /ai/fixture; do N=20 bench $r >/dev/null; done
read -r b50 b95 bmean <<<"$(bench /ai/baseline)"
read -r o50 o95 omean <<<"$(bench /ai/fixture)"
printf "\n%-32s %8s %8s %8s\n" "route (N=$N, client-side ms)" p50 p95 mean
printf "%-32s %8s %8s %8s\n" "/ai/baseline (no observer)" "$b50" "$b95" "$bmean"
printf "%-32s %8s %8s %8s\n" "/ai/fixture  (observer+tail)" "$o50" "$o95" "$omean"
python3 -c "print(f'observer overhead estimate: p50 {float(\"$o50\")-float(\"$b50\"):+.2f} ms, p95 {float(\"$o95\")-float(\"$b95\"):+.2f} ms, mean {float(\"$omean\")-float(\"$bmean\"):+.2f} ms (includes 2 extra plugins + enrichment of the http-log event)')"

echo; echo "Kong-side latency headers (last request): $(curl -sS -D - -o /dev/null -H "apikey: $RUNNER_APIKEY" -H 'Content-Type: application/json' -H 'Accept-Encoding: identity' -d "$BODY" $KONG/ai/fixture | grep -i 'x-kong-.*latency' | tr '\n' ' ')"

echo; echo "bounded memory: 30 x ~1 MiB responses per route (observer capture mode bounded, 2 KiB prefix). RSS of all Kong workers."
rss() { docker compose exec -T kong sh -c "ps -o rss= -p \$(pgrep -d, -f 'nginx: worker') | awk '{s+=\$1} END {print s}'" | tr -d ' '; }
burst() { for i in $(seq 1 30); do curl -sS -o /dev/null -H "apikey: $RUNNER_APIKEY" -H 'Content-Type: application/json' -H 'Accept-Encoding: identity' \
       -d '{"model":"mock-gpt","messages":[{"role":"user","content":"big respond:LARGE:1024"}]}' "$KONG$1"; done; }
burst /ai/baseline; burst /ai/fixture   # warm both paths once (LuaJIT/ai-proxy buffers)
b0=$(rss); burst /ai/baseline; b1=$(rss)
o0=$(rss); burst /ai/fixture;  o1=$(rss)
echo "kong workers RSS delta: baseline route $((b1-b0)) KiB, observed route $((o1-o0)) KiB (ai-proxy buffers whole bodies on both; the difference is the observer's share)"
echo "last observation stream/tail capture sizes:"
curl -sS "http://localhost:${EVALUATOR_PORT:-8800}/observations/recent?limit=1" | python3 -c "
import sys,json; o=json.load(sys.stdin)[0]
for k in ('stream','tail'):
    s=o.get(k) or {}; print(f\"  {k}: chunks={s.get('chunks')} bytes={s.get('bytes')} prefix_kept={len(s.get('body_prefix') or '')} truncated={s.get('body_truncated')} timeline_entries={len(s.get('timeline') or [])}\")"
