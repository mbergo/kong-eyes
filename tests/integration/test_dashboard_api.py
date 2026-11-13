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
    assert t["stopped"] == sum(g["stopped"] for g in o["guardrails"]) + t["stopped_elsewhere"]      # the flow picture adds up
    assert len(o["guardrails"]) == 2 and all(g["reached"] > 0 for g in o["guardrails"])
    first, second = o["guardrails"]
    assert first["stopped"] > 0 and second["stopped"] > 0                         # plain and disguised attack bursts
    assert second["fail_open"] > 0 and second["time_ms"]["max"] >= 350             # the slow burst: waited about 400 ms, then let through
    assert t["waited"] == sum(g["fail_open"] for g in o["guardrails"])
    assert [c["kind"] for c in o["chain"]] == ["guardrail", "guardrail", "router"]
    assert o["plain"][0].startswith("In the last 60 seconds") and first["name"] in " ".join(o["plain"]) and "may not have been checked" in " ".join(o["plain"])


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
    external = re.findall(r"""(?:src|href)\s*=\s*["']((?:https?:)?//[^"']+)""", page) + re.findall(r"""url\(\s*["']?((?:https?:)?//[^)"']+)""", page)
    assert not external, external                                                    # no CDN, fonts or scripts from anywhere else


def test_dashboard_links_the_other_pages_and_says_how_to_connect_a_kong():
    page = get("/dashboard", raw=True)
    assert 'href="chain"' in page and 'href="demo"' in page and "Connect your Kong" in page
    c = get("/api/connect")
    assert c["ingest_url"].endswith("/ingest/kong") and c["ingest_token"] == ENV["INGEST_TOKEN"]


def test_the_3d_page_explains_what_its_shapes_mean():
    page = get("/chain", raw=True)
    assert "How to read this" in page and "Start, on the left" in page and "over-flagging?" in page and "What each guardrail is doing" in page and 'href="dashboard"' in page


def test_pages_load_their_data_from_their_own_address():
    for p in ("/dashboard", "/chain", "/demo"):
        assert "fetch from the page's own address" in get(p, raw=True), p
    assert "POST /passive/translate" not in get("/chain", raw=True)


def test_each_gateway_that_sends_data_gets_its_own_box_with_nodes_routes_and_models(traffic):
    d = get("/api/gateways")
    mine = [g for g in d["gateways"] if any(r["name"] == ROUTE for r in g["routes"])]
    assert len(mine) == 1, d
    g = mine[0]
    assert g["name"] and g["events"] > 0 and g["sending"] is True and g["last_seen_ms"] >= g["first_seen_ms"]
    assert g["nodes"] and g["nodes"][0]["address"] and "name" in g["nodes"][0]
    r = next(r for r in g["routes"] if r["name"] == ROUTE)
    assert r["events"] > 0 and r["models"] and set(r["models"]) <= set(g["models"])       # the model behind the route is named
    page = get("/dashboard", raw=True)
    assert 'id="where"' in page and 'id="gws"' in page and "You are looking at gateway" in page
