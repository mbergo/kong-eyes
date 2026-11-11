"""Integration: `koe demo traffic` drives the demo route hard and the collector keeps up.

Needs the stack up with the stand-in guardrails (scripts/gen-demo-guards.sh) so that /ai/named exists.
"""
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
ENV_FILE = pathlib.Path(os.environ.get("KE_ENV_FILE", ROOT / ".env"))
ENV = dict(l.rstrip("\n").split("=", 1) for l in ENV_FILE.read_text().splitlines() if "=" in l and not l.startswith("#")) if ENV_FILE.exists() else {}
PROXY = f"http://localhost:{ENV.get('KONG_PROXY_PORT', '8000')}"
EVAL = f"http://localhost:{ENV.get('EVALUATOR_PORT', '8800')}"
OPEN = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(url):
    with OPEN.open(url, timeout=30) as r:
        return json.loads(r.read())


def test_storm_traffic_reaches_the_collector_and_moves_the_numbers():
    try:
        get(EVAL + "/health")
    except (urllib.error.URLError, OSError):
        pytest.skip("the collector is not reachable")
    env = dict(os.environ, PYTHONPATH=str(ROOT / "cli"), NO_PROXY="localhost,127.0.0.1")
    r = subprocess.run([sys.executable, "-m", "kong_eyes", "demo", "traffic", "--kong-url", PROXY, "--apikey", ENV["RUNNER_APIKEY"],
                        "--rps", "50", "--minutes", "0.4", "--report-s", "4"], env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout[-800:] + r.stderr[-400:]
    done = r.stdout.strip().splitlines()[-1]
    total = int(done.split("done: ")[1].split(" ")[0])
    assert total >= 600, done                                        # about 50/s for 24 s, minus ramp
    assert " 200=" in done and " 403=" in done and "ERR=" not in done, done
    if "/ai/named" not in r.stdout:
        pytest.skip("not the stand-in route")
    assert "attack" in r.stdout                                      # the mix really changed during the run

    time.sleep(6)                                                    # Kong's log queue and the ingest
    s = get(EVAL + "/passive/summary?window_s=40&route=ai-named-route")
    route = s["routes"].get("ai-named-route")
    assert route and route["requests"] >= total * 0.8, (route or {}).get("requests")
    stopped = sum(g["blocked"] for g in s["guardrails"].values())
    assert stopped >= 20, stopped                                    # the attack burst shows up as stops, attributed to a guardrail
    t0 = time.time(); get(EVAL + "/passive/summary?window_s=40"); assert time.time() - t0 < 2.0   # the collector still answers quickly
