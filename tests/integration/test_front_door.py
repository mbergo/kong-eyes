"""Integration: the HTTPS front door asks for one user and password, and leaves the two machine paths alone.

Runs the real deploy/Caddyfile in a throwaway Caddy container on the stack's network, with a generated login.
Needs Docker and the stack up.
"""
import json
import os
import pathlib
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.request
import base64

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
ENV_FILE = pathlib.Path(os.environ.get("KE_ENV_FILE", ROOT / ".env"))
ENV = dict(l.rstrip("\n").split("=", 1) for l in ENV_FILE.read_text().splitlines() if "=" in l and not l.startswith("#")) if ENV_FILE.exists() else {}
PORT, NAME, USER, PW = 18447, "koe-it-front-door", "tester", "it-pass-!x"
CTX = ssl._create_unverified_context()                      # Caddy signs "localhost" with its own local authority
OPEN = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=CTX), type("NoRedirect", (urllib.request.HTTPRedirectHandler,), {"redirect_request": lambda *a, **k: None}))


def call(path, method="GET", auth=None, body=None, headers=None):
    h = dict(headers or {})
    if auth:
        h["Authorization"] = "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req = urllib.request.Request(f"https://localhost:{PORT}{path}", method=method, headers=h, data=body)
    try:
        with OPEN.open(req, timeout=20) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


@pytest.fixture(scope="module")
def front_door(tmp_path_factory):
    if not shutil.which("docker"):
        pytest.skip("docker is not available")
    net = subprocess.run(["docker", "network", "ls", "--format", "{{.Name}}"], capture_output=True, text=True).stdout.split()
    net = next((n for n in net if n.endswith("_default") and "guardrail" in n), None)
    if not net:
        pytest.skip("the stack's network was not found; is the stack up?")
    d = tmp_path_factory.mktemp("caddy")
    shutil.copy(ROOT / "deploy" / "Caddyfile", d / "Caddyfile")
    h = subprocess.run(["docker", "run", "--rm", "-e", f"KOE_PW={PW}", "caddy:2-alpine", "sh", "-c", 'caddy hash-password --plaintext "$KOE_PW"'],
                       capture_output=True, text=True, timeout=120).stdout.strip().splitlines()[-1]
    (d / "auth.caddy").write_text("basic_auth {\n\t%s %s\n}\n" % (USER, h))
    os.chmod(d, 0o755)
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
    r = subprocess.run(["docker", "run", "-d", "--name", NAME, "--network", net, "-e", "EYES_DOMAIN=localhost", "-p", f"127.0.0.1:{PORT}:443",
                        "-v", f"{d}:/etc/caddy:ro", "caddy:2-alpine"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    for _ in range(30):
        try:
            call("/dashboard"); break
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    yield
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)


def test_everything_human_asks_for_the_password(front_door):
    for path in ("/dashboard", "/chain", "/api/overview", "/api/requests", "/passive/summary", "/demo", "/metrics"):
        status, headers, _ = call(path)
        assert status == 401 and headers.get("Www-Authenticate", headers.get("WWW-Authenticate", "")).lower().startswith("basic"), (path, status)
    assert call("/dashboard", auth=(USER, "wrong"))[0] == 401
    status, _, body = call("/dashboard", auth=(USER, PW))
    assert status == 200 and b"Where the requests went" in body
    assert call("/api/overview?window_s=60", auth=(USER, PW))[0] == 200
    assert call("/chain", auth=(USER, PW))[0] == 200


def test_the_dashboard_is_the_home_page(front_door):
    status, headers, _ = call("/", auth=(USER, PW))
    assert status == 302 and headers.get("Location", "").endswith("/dashboard")


def test_machine_paths_use_their_own_keys_not_the_password(front_door):
    # Kong posts events here with the collector's ingest token and no front-door login
    ok = call("/ingest/kong", method="POST", auth=("kong", ENV["INGEST_TOKEN"]), body=b"[]", headers={"Content-Type": "application/json"})
    assert ok[0] == 200, ok
    assert call("/ingest/kong", method="POST", auth=("kong", "not-the-token"), body=b"[]", headers={"Content-Type": "application/json"})[0] in (401, 403)
    # the demo Kong answers by its own rules: no key, no entry
    status, _, body = call("/kong/ai/named", method="POST", body=b"{}", headers={"Content-Type": "application/json"})
    assert status == 401 and b"API key" in body
