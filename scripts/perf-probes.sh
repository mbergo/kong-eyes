#!/usr/bin/env bash
# Probe overhead, A/B: /ai/fixture (head + tail) vs /ai/fixture-probes (head + tail + three middle probes).
# Interleaved requests over one keep-alive connection per route; prints client-side percentiles and the difference.
# Boundary: includes the mock model and Docker networking on both sides; only the difference is attributable.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
N=${N:-400} KONG="http://localhost:${KONG_PROXY_PORT:-8000}" python3 - <<'PY'
import http.client, json, os, statistics, time, urllib.parse
n = int(os.environ["N"]); u = urllib.parse.urlparse(os.environ["KONG"])
body = json.dumps({"model": "mock-gpt", "messages": [{"role": "user", "content": "Plain benign prompt. respond:CLEAN"}]})
hdr = {"Content-Type": "application/json", "apikey": os.environ["RUNNER_APIKEY"], "Accept-Encoding": "identity"}
conns = {p: http.client.HTTPConnection(u.hostname, u.port, timeout=30) for p in ("/ai/fixture", "/ai/fixture-probes")}
t = {p: [] for p in conns}
for i in range(n + 20):
    for p in (list(conns) if i % 2 == 0 else list(conns)[::-1]):      # alternate the order to cancel drift
        t0 = time.perf_counter(); c = conns[p]; c.request("POST", p, body=body, headers=hdr); r = c.getresponse(); r.read()
        assert r.status == 200, (p, r.status)
        if i >= 20: t[p].append((time.perf_counter() - t0) * 1000)   # first 20 are warm-up
def q(xs, f): xs = sorted(xs); return xs[min(len(xs) - 1, int(f * len(xs)))]
for p, xs in t.items():
    print(f"{p:<20} n={len(xs)} p50={q(xs, .5):.3f} ms  p95={q(xs, .95):.3f} ms  mean={statistics.mean(xs):.3f} ms")
a, b = t["/ai/fixture"], t["/ai/fixture-probes"]
print(f"three probes add: p50 {q(b, .5) - q(a, .5):+.3f} ms  p95 {q(b, .95) - q(a, .95):+.3f} ms  mean {statistics.mean(b) - statistics.mean(a):+.3f} ms")
PY
