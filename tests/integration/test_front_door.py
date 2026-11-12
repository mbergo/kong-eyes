"""Integration: a public install asks people to sign in once, and leaves the path gateways post to alone.

Runs the real deploy/Caddyfile in a Caddy container in front of a throwaway collector container with sign-in
switched on, on their own network. Needs Docker and the collector image (built by the stack).
"""
import base64
import hashlib
import json
import pathlib
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
IMAGE = "guardrail-observer/evaluator:local"
PORT, NET, CADDY, COLLECTOR = 18447, "koe-it-front-door", "koe-it-front-door-caddy", "koe-it-front-door-collector"
USER, PW, TOKEN = "tester", "it-pass-!x", "it-ingest-token"
CTX = ssl._create_unverified_context()                      # Caddy signs "localhost" with its own local authority
NoRedirect = type("NoRedirect", (urllib.request.HTTPRedirectHandler,), {"redirect_request": lambda *a, **k: None})
OPEN = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=CTX), NoRedirect)
HTML = {"Accept": "text/html"}


def call(path, method="GET", body=None, headers=None, cookie=None):
    h = dict(headers or {})
    if cookie:
        h["Cookie"] = cookie
    req = urllib.request.Request(f"https://localhost:{PORT}{path}", method=method, headers=h, data=body)
    try:
        with OPEN.open(req, timeout=20) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def sign_in(user, password, nxt="/chain"):
    form = urllib.parse.urlencode({"username": user, "password": password, "next": nxt}).encode()
    status, headers, body = call("/login", "POST", form, {"Content-Type": "application/x-www-form-urlencoded"})
    return status, headers, body, (headers.get("Set-Cookie") or "").split(";")[0]


def docker(*a, **k):
    return subprocess.run(["docker", *a], capture_output=True, text=True, **k)


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    if not shutil.which("docker"):
        pytest.skip("docker is not available")
    if not docker("image", "inspect", IMAGE).stdout.strip().startswith("["):
        pytest.skip(f"{IMAGE} is not built; bring the stack up first")
    d = tmp_path_factory.mktemp("caddy"); d.chmod(0o755)
    shutil.copy(ROOT / "deploy" / "Caddyfile", d / "Caddyfile")
    salt = bytes(range(16))
    pw_hash = "pbkdf2:200000:%s:%s" % (salt.hex(), hashlib.pbkdf2_hmac("sha256", PW.encode(), salt, 200000).hex())
    docker("rm", "-f", CADDY, COLLECTOR); docker("network", "rm", NET)
    assert docker("network", "create", NET).returncode == 0
    r = docker("run", "-d", "--name", COLLECTOR, "--network", NET, "--network-alias", "evaluator", "-e", f"INGEST_TOKEN={TOKEN}",
               "-e", f"FRONT_DOOR_USER={USER}", "-e", f"FRONT_DOOR_HASH={pw_hash}", "-e", "FRONT_DOOR_SECRET=it-secret-0123456789", IMAGE)
    assert r.returncode == 0, r.stderr
    r = docker("run", "-d", "--name", CADDY, "--network", NET, "-e", "EYES_DOMAIN=localhost", "-p", f"127.0.0.1:{PORT}:443",
               "-v", f"{d}:/etc/caddy:ro", "caddy:2-alpine")
    assert r.returncode == 0, r.stderr
    for _ in range(40):
        try:
            if call("/health")[0] == 200:
                break
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(1)
    yield
    docker("rm", "-f", CADDY, COLLECTOR); docker("network", "rm", NET)


def test_without_a_session_pages_go_to_sign_in_and_data_is_refused(site):
    for path in ("/", "/dashboard", "/chain", "/demo"):
        status, headers, _ = call(path, headers=HTML)
        assert status == 302 and headers["Location"].startswith("/login?next="), (path, status, headers.get("Location"))
    for path in ("/api/overview", "/api/requests", "/api/connect", "/passive/summary", "/metrics", "/demo/state"):
        assert call(path)[0] == 401, path
    status, _, body = call("/login", headers=HTML)
    assert status == 200 and b"Sign in" in body and b'name="password"' in body


def test_one_sign_in_opens_everything_and_lands_where_the_person_was_going(site):
    status, _, body, cookie = sign_in(USER, "wrong")
    assert status == 401 and b"do not match" in body and not cookie
    assert sign_in("someone-else", PW)[0] == 401
    status, headers, _, cookie = sign_in(USER, PW, nxt="/chain")
    assert status == 303 and headers["Location"] == "/chain" and cookie.startswith("koe_session=")
    flags = headers["Set-Cookie"].lower()
    assert "httponly" in flags and "secure" in flags and "samesite=lax" in flags and "max-age=604800" in flags
    for path in ("/dashboard", "/chain", "/api/overview?window_s=60", "/api/connect"):
        assert call(path, headers=HTML, cookie=cookie)[0] == 200, path
    status, headers, _ = call("/", headers=HTML, cookie=cookie)
    assert status == 302 and headers["Location"].endswith("dashboard")
    assert json.loads(call("/api/session", cookie=cookie)[2]) == {"sign_in": True, "user": USER}


def test_a_forged_session_or_an_outside_address_gets_nowhere(site):
    _, _, _, cookie = sign_in(USER, PW)
    expires, sig = cookie.split("=", 1)[1].split(".", 1)
    assert call("/api/overview", cookie=f"koe_session={int(expires) + 86400}.{sig}")[0] == 401
    assert call("/api/overview", cookie="koe_session=nonsense")[0] == 401
    assert sign_in(USER, PW, nxt="https://example.org/")[1]["Location"] == "/dashboard"
    assert sign_in(USER, PW, nxt="//example.org/")[1]["Location"] == "/dashboard"
    status, headers, _ = call("/logout", cookie=cookie)
    assert status == 302 and headers["Location"] == "/login" and "koe_session=" in headers["Set-Cookie"]


def test_gateways_post_events_with_the_collector_token_and_no_session(site):
    basic = lambda t: {"Authorization": "Basic " + base64.b64encode(f"kong:{t}".encode()).decode(), "Content-Type": "application/json"}
    assert call("/ingest/kong", "POST", b"[]", basic(TOKEN))[0] == 200
    assert call("/ingest/kong", "POST", b"[]", basic("not-the-token"))[0] in (401, 403)
