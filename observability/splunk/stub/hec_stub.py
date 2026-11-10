"""Minimal Splunk HEC-compatible stub for LOCAL exporter validation.

Implements: POST /services/collector/event (newline-delimited envelopes), token auth,
HEC response codes ({"text":"Success","code":0} / 401 code 4 / 400 code 6), optional
ack channel (X-Splunk-Request-Channel -> ackId; POST /services/collector/ack),
GET /services/collector/health, and GET /_events?smoke_id=... for tests to verify receipt.
Validates the stub, not Splunk: a passing stub run means the envelope and
protocol handling are right, nothing more.
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

TOKEN = os.environ.get("HEC_TOKEN", "stub-token")
FAIL_MODE = {"value": os.environ.get("HEC_FAIL", "")}  # "" | "503" | "unauth" - toggled via POST /_fail?mode=
EVENTS: list[dict] = []
ACKS: dict[int, bool] = {}
LOCK = threading.Lock()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _json(self, code: int, body: dict):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/services/collector/health":
            return self._json(200, {"text": "HEC is healthy", "code": 17})
        if u.path == "/_events":
            q = parse_qs(u.query)
            with LOCK:
                evs = EVENTS
                if "smoke_id" in q:
                    evs = [e for e in evs if (e.get("event") or {}).get("smoke_id") == q["smoke_id"][0]]
                if "event_id" in q:
                    evs = [e for e in evs if (e.get("event") or {}).get("event_id") == q["event_id"][0]]
                return self._json(200, {"count": len(evs), "events": evs[-50:]})
        if u.path == "/_stats":
            with LOCK:
                return self._json(200, {"events": len(EVENTS), "fail_mode": FAIL_MODE["value"]})
        self._json(404, {"text": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        if u.path == "/_fail":
            FAIL_MODE["value"] = parse_qs(u.query).get("mode", [""])[0]
            return self._json(200, {"fail_mode": FAIL_MODE["value"]})
        if FAIL_MODE["value"] == "503":
            return self._json(503, {"text": "Server is busy", "code": 9})
        auth = self.headers.get("Authorization", "")
        if FAIL_MODE["value"] == "unauth" or auth != f"Splunk {TOKEN}":
            return self._json(401, {"text": "Invalid token", "code": 4})
        if u.path == "/services/collector/ack":
            try:
                acks = json.loads(raw.decode()).get("acks", [])
            except Exception:  # noqa: BLE001
                return self._json(400, {"text": "Invalid data format", "code": 6})
            return self._json(200, {"acks": {str(a): ACKS.get(int(a), False) for a in acks}})
        if u.path in ("/services/collector/event", "/services/collector", "/services/collector/event/1.0"):
            envs = []
            for line in raw.decode(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    env = json.loads(line)
                except Exception:  # noqa: BLE001
                    return self._json(400, {"text": "Invalid data format", "code": 6})
                if "event" not in env:
                    return self._json(400, {"text": "No data", "code": 5})
                envs.append(env)
            with LOCK:
                EVENTS.extend(envs)
                resp = {"text": "Success", "code": 0}
                if self.headers.get("X-Splunk-Request-Channel"):
                    ack_id = len(ACKS) + 1
                    ACKS[ack_id] = True
                    resp["ackId"] = ack_id
            return self._json(200, resp)
        self._json(404, {"text": "not found"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8088"))
    print(f"hec stub on :{port} token={TOKEN}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
