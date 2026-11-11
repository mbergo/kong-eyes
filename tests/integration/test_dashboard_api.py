"""Integration: the in-house dashboard gets everything from the collector, with no Grafana, Loki or Prometheus.

Needs the stack up with the stand-in guardrails so that /ai/named exists. Sends real traffic through Kong first.
"""
import json
import os
import pathlib
import re
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
ROUTE = "ai-named-route"


def get(path, raw=False):
    with OPEN.open(EVAL + path, timeout=30) as r:
        b = r.read()
        return b.decode() if raw else json.loads(b)


@pytest.fixture(scope="module")
def traffic():
    try:
        get("/health")
    except (urllib.error.URLError, OSError):
        pytest.skip("the collector is not reachable")
    env = dict(os.environ, PYTHONPATH=str(ROOT / "cli"), NO_PROXY="localhost,127.0.0.1")
    r = subprocess.run([sys.executable, "-m", "kong_eyes", "demo", "traffic", "--kong-url", PROXY, "--apikey", ENV["RUNNER_APIKEY"],
                        "--rps", "40", "--minutes", "0.5"], env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout[-600:] + r.stderr[-300:]
    time.sleep(6)
    return int(r.stdout.strip().splitlines()[-1].split("done: ")[1].split(" ")[0])


def test_overview_says_in_plain_words_what_each_guardrail_did(traffic):
    o = get(f"/api/overview?window_s=60&route={ROUTE}")
    t = o["totals"]
    assert o["route"] == ROUTE and t["requests"] >= traffic * 0.8 and t["served"] + t["stopped"] == t["requests"]
    assert len(o["guardrails"]) == 2 and all(g["reached"] > 0 for g in o["guardrails"])
    first, second = o["guardrails"]
    assert first["stopped"] > 0 and second["stopped"] > 0                         # plain and disguised attack bursts
    assert second["fail_open"] > 0 and second["time_ms"]["max"] >= 350             # the slow burst: waited about 400 ms, then let through
    assert t["waited"] == sum(g["fail_open"] for g in o["guardrails"])
    assert [c["kind"] for c in o["chain"]] == ["guardrail", "guardrail", "router"]
    assert o["plain"][0].startswith("In the last 60 seconds") and first["name"] in " ".join(o["plain"]) and "let through" in " ".join(o["plain"])


def test_timeseries_and_request_list_come_from_the_collector_store(traffic):
    ts = get(f"/api/timeseries?window_s=60&buckets=30&route={ROUTE}")
    names = [o["name"] for o in ts["outcomes"]]
    assert names[0] == "served" and any(n.startswith("stopped by ") for n in names) and any(n.startswith("waited at ") for n in names), names
    total = sum(sum(o["values"]) for o in ts["outcomes"])
    assert total >= traffic * 0.8
    assert sum(1 for o in ts["outcomes"] if o["name"] == "served" for v in o["values"] if v) >= 10      # spread over time, not one lump
    assert max(v for v in ts["gateway_ms"]["p95"] if v is not None) >= 350 and max(v for v in ts["guardrail_ms"]["p95"] if v is not None) >= 350

    rows = get(f"/api/requests?limit=50&route={ROUTE}")["requests"]
    assert len(rows) == 50 and rows[0]["at_ms"] >= rows[-1]["at_ms"]
    assert all(r["result"] and r["steps"] for r in rows)
    stopped = get(f"/api/requests?limit=20&route={ROUTE}&result=stopped")["requests"]
    assert stopped and all(r["result"].startswith("stopped by ") and r["steps"][-1]["stopped"] and r["status"] == 403 for r in stopped)
    waited = get(f"/api/requests?limit=5&route={ROUTE}&result=waited")["requests"]
    assert waited and all(r["total_ms"] >= 350 for r in waited)


def test_dashboard_page_is_self_contained(traffic):
    page = get("/dashboard", raw=True)
    assert "Where the requests went" in page and "api/overview" in page
    external = [u for u in re.findall(r'(?:src|href)="(https?://[^"]+)"', page)] + re.findall(r"url\((https?://[^)]+)\)", page)
    assert not external, external                                                    # no CDN, fonts or scripts from anywhere else
