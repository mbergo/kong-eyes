"""Integration: `koe connect` with bundled plugins only, against a running Kong and collector.

Needs the local stack up (make up) and reads its ports and tokens from the stack's .env:
  KE_ENV_FILE=/path/to/.env pytest tests/integration        (default: ./.env)
Skipped when Kong's Admin API is not reachable.

It builds a throwaway route with one guardrail (the repo's synthetic fixture), connects Kong Eyes to it through
the CLI, sends real requests through Kong, and checks what the collector concluded. Then it removes everything.
"""
import copy
import http.client
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

yaml = pytest.importorskip("yaml")
ROOT = pathlib.Path(__file__).resolve().parents[2]
ENV_FILE = pathlib.Path(os.environ.get("KE_ENV_FILE", ROOT / ".env"))
ENV = dict(l.rstrip("\n").split("=", 1) for l in ENV_FILE.read_text().splitlines() if "=" in l and not l.startswith("#")) if ENV_FILE.exists() else {}
ADMIN = f"http://localhost:{ENV.get('KONG_ADMIN_PORT', '8001')}"
PROXY_PORT = int(ENV.get("KONG_PROXY_PORT", "8000"))
EVAL = f"http://localhost:{ENV.get('EVALUATOR_PORT', '8800')}"
ROUTE, RID, GUARD, SLOW_MS = "ke-it-bundled", "0b3c1f6e-7a52-4c1d-9a44-6f2d1e8b9c01", "fixture-input-guard", 300
OPEN = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(method, url, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method=method, headers={"Content-Type": "application/json"})
    with OPEN.open(req, timeout=60) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def cli(*args):
    env = dict(os.environ, PYTHONPATH=str(ROOT / "cli"), KONG_ADMIN_URL=ADMIN, NO_PROXY="localhost,127.0.0.1")
    return subprocess.run([sys.executable, "-m", "kong_eyes", *args], env=env, capture_output=True, text=True, timeout=120)


def send(text, key):
    c = http.client.HTTPConnection("localhost", PROXY_PORT, timeout=30)
    c.request("POST", f"/{ROUTE}", body=json.dumps({"model": "mock-gpt", "messages": [{"role": "user", "content": text}]}),
              headers={"Content-Type": "application/json", "apikey": key})
    r = c.getresponse(); r.read()
    return r.status


@pytest.fixture(scope="module")
def gateway():
    try:
        info = api("GET", ADMIN + "/")
    except (urllib.error.URLError, OSError):
        pytest.skip(f"Kong's Admin API is not reachable at {ADMIN}")
    if info["configuration"].get("database") != "off":
        pytest.skip("this test builds its route through DB-less /config")
    if GUARD not in info["plugins"]["available_on_server"]:
        pytest.skip(f"the gateway image does not carry {GUARD}")
    original = yaml.safe_load(api("GET", ADMIN + "/config")["config"])
    cfg = copy.deepcopy(original)
    svc = next(s for s in cfg["services"] if s["name"] == "mock-llm")
    cfg["routes"].append({"id": RID, "name": ROUTE, "paths": [f"/{ROUTE}"], "strip_path": True, "service": svc["id"], "protocols": ["http", "https"]})
    for name, conf in [("key-auth", {"key_names": ["apikey"], "hide_credentials": True}),
                       (GUARD, {"mode": "block", "slow_ms": SLOW_MS}),
                       ("ai-proxy", {"route_type": "llm/v1/chat", "auth": {"header_name": "Authorization", "header_value": "Bearer mock-key"},
                                     "model": {"provider": "openai", "name": "mock-gpt", "options": {"upstream_url": "http://mock-llm:8080/v1/chat/completions"}}})]:
        cfg["plugins"].append({"name": name, "route": RID, "config": conf, "enabled": True, "protocols": ["http", "https"]})
    api("POST", ADMIN + "/config?check_hash=0", {"config": yaml.safe_dump(cfg)})
    yield
    api("POST", ADMIN + "/config?check_hash=0", {"config": yaml.safe_dump(original)})


def test_connect_reports_one_guardrail_through_bundled_plugins(gateway):
    # dry run changes nothing and guesses the guardrail: it is the only plugin on the route Kong does not ship
    r = cli("connect", "--route", ROUTE, "--ingest-url", "http://evaluator:8000/ingest/kong", "--dry-run")
    assert r.returncode == 0, r.stderr + r.stdout
    assert f"guardrail              {GUARD}" in r.stdout and "guessed" in r.stdout and "nothing changed" in r.stdout
    assert not [p for p in api("GET", f"{ADMIN}/routes/{ROUTE}/plugins")["data"] if "kong-eyes" in (p.get("tags") or [])]

    r = cli("connect", "--route", ROUTE, "--ingest-url", "http://evaluator:8000/ingest/kong", "--ingest-token", ENV["INGEST_TOKEN"],
            "--timeout-ms", str(SLOW_MS), "--show-prompts", "200", "--environment", "it", "--yes")
    assert r.returncode == 0, r.stderr + r.stdout
    mine = sorted(p["name"] for p in api("GET", f"{ADMIN}/routes/{ROUTE}/plugins")["data"] if "kong-eyes" in (p.get("tags") or []))
    assert mine == ["http-log", "post-function", "pre-function"]
    assert ROUTE in cli("status").stdout
    # connecting twice updates in place
    assert cli("connect", "--route", ROUTE, "--ingest-url", "http://evaluator:8000/ingest/kong", "--ingest-token", ENV["INGEST_TOKEN"],
               "--timeout-ms", str(SLOW_MS), "--show-prompts", "200", "--environment", "it", "--yes").returncode == 0
    assert len(api("GET", f"{ADMIN}/routes/{ROUTE}/plugins")["data"]) == 6

    time.sleep(2)
    key = ENV["RUNNER_APIKEY"]
    sent = ([send(f"benign {i} respond:CLEAN", key) for i in range(6)] + [send(f"attack {i} [[VIOLATION]]", key) for i in range(3)]
            + [send(f"[[FIXTURE_SLOW]] slow {i} respond:CLEAN", key) for i in range(2)] + [send("no key respond:CLEAN", "wrong-key")])
    assert sent == [200] * 6 + [403] * 3 + [200] * 2 + [401]

    deadline, s = time.time() + 40, None
    while time.time() < deadline:
        s = api("GET", f"{EVAL}/passive/summary?window_s=300&route={ROUTE}")
        if (s["routes"].get(ROUTE) or {}).get("requests", 0) >= 12:
            break
        time.sleep(2)
    route, g = s["routes"][ROUTE], s["guardrails"][GUARD]
    assert route["requests"] == 12 and route["blocked"] == 4            # three by the guardrail, one by authentication
    assert g["blocked"] == 3, g                                         # stops named by elimination, not by the fixture's own events
    assert g["fail_open_suspects"] == 2, g                              # waited about the timeout, then let through
    assert g["latency_ms"]["max"] >= SLOW_MS - 10, g                    # the bracket measured the wait
    assert [c["name"] for c in route["chain"] if c["kind"] == "guardrail"] == [GUARD]
    assert any(x["kind"] == "suspected_fail_open" and x.get("guardrail") == GUARD for x in s["signals"])

    r = cli("disconnect", "--route", ROUTE, "--yes")
    assert r.returncode == 0 and "removed" in r.stdout
    assert sorted(p["name"] for p in api("GET", f"{ADMIN}/routes/{ROUTE}/plugins")["data"]) == ["ai-proxy", GUARD, "key-auth"]


def test_without_a_route_it_lists_the_routes_to_choose_from(gateway):
    r = cli("connect", "--ingest-url", "http://collector.invalid/ingest/kong", "--dry-run")
    out = r.stdout + r.stderr
    assert "A route is one entry point" in out and "ai-named-route" in out and "/ai/named" in out, out[-800:]
    assert r.returncode != 0 and "--route NAME" in out   # several routes and no terminal: it asks for the name, and changes nothing


def test_konnect_is_driven_through_its_own_api_with_a_personal_access_token(gateway):
    """A stand-in for Konnect's API in front of the real Kong: bearer token, control planes, routes by id only, plugins written with PUT."""
    import http.server
    import re
    import threading
    writes, port = [], 18449

    class Konnect(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def answer(self, code, obj):
            raw = json.dumps(obj).encode()
            self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

        def handle_any(self):
            if self.headers.get("Authorization") != "Bearer kpat_test":
                return self.answer(401, {"message": "Unauthorized"})
            if self.path.startswith("/v2/control-planes?"):
                return self.answer(200, {"data": [{"id": "cp-1", "name": "demo-cp"}, {"id": "cp-2", "name": "other-cp"}], "meta": {"page": {"total": 2}}})
            m = re.match(r"/v2/control-planes/cp-1/core-entities(/.*)", self.path)
            if not m:
                return self.answer(404, {"message": "Not Found"})
            rest = m.group(1)
            if self.command == "PUT":
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                writes.append((rest, body))
                return self.answer(200, body)
            if re.match(r"/routes/[^/?]+$", rest) and not re.match(r"/routes/[0-9a-f-]{36}$", rest):
                return self.answer(404, {"message": "Not Found"})          # Konnect looks routes up by id only
            return self.answer(200, api("GET", ADMIN + rest))

        do_GET = do_PUT = handle_any

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Konnect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        env = dict(os.environ, PYTHONPATH=str(ROOT / "cli"), NO_PROXY="localhost,127.0.0.1", KONNECT_API_URL=f"http://localhost:{port}", HOME="/nonexistent")
        run = lambda *a, token="kpat_test": subprocess.run([sys.executable, "-m", "kong_eyes", *a], env=dict(env, KONNECT_TOKEN=token), capture_output=True, text=True, timeout=120)
        base = ("connect", "--route", ROUTE, "--ingest-url", "https://collector.example/ingest/kong", "--ingest-token", "tok", "--yes")
        r = run(*base)                                              # two control planes and no terminal: it names them and changes nothing
        assert r.returncode != 0 and "demo-cp" in r.stdout + r.stderr and "other-cp" in r.stdout + r.stderr and not writes, r.stdout + r.stderr
        r = run(*base, token="kpat_wrong")
        assert r.returncode != 0 and "personal access token" in r.stderr and not writes
        r = run(*base, "--control-plane", "demo-cp")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Konnect, control plane demo-cp" in r.stdout and f"guardrail              {GUARD}" in r.stdout and "connected." in r.stdout
        assert sorted(b["name"] for _, b in writes) == ["http-log", "post-function", "pre-function"]
        for path, b in writes:
            assert path == f"/plugins/{b['id']}" and b["route"] == {"id": RID} and b["tags"] == ["kong-eyes"]
        log = next(b for _, b in writes if b["name"] == "http-log")
        assert log["config"]["http_endpoint"] == "https://kong:tok@collector.example/ingest/kong" and "guardrail_observer" in log["config"]["custom_fields_by_lua"]
        assert 'model = "mock-gpt"' in log["config"]["custom_fields_by_lua"]["guardrail_observer"]              # read from the route's ai-proxy
        assert 'gateway = "demo-cp (Konnect)"' in log["config"]["custom_fields_by_lua"]["guardrail_observer"]      # the dashboard names the gateway from this
    finally:
        srv.shutdown()
