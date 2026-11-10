"""Splunk HTTP Event Collector exporter.

Endpoint: <SPLUNK_HEC_URL>/services/collector/event   (JSON event endpoint)
Auth:     Authorization: Splunk <token>
Envelope: {"time": <epoch seconds>, "host", "source", "sourcetype", "index", "event": {...}}
Success:  HTTP 200 AND body {"text":"Success","code":0}. Anything else is a failure.
ACKs:     when SPLUNK_HEC_ACK=true we send X-Splunk-Request-Channel and poll
          /services/collector/ack until the ackId is true; acceptance != indexed otherwise.
Acceptance is never equated with search visibility; the smoke test reports both.
"""
from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass


@dataclass
class SplunkConfig:
    url: str
    token: str
    index: str | None = None
    sourcetype: str = "kong:guardrail:evaluation"
    source: str = "guardrail-evaluator"
    host: str = os.uname().nodename if hasattr(os, "uname") else "evaluator"
    verify_tls: bool = True
    ca_file: str | None = None
    use_ack: bool = False
    ack_timeout_s: float = 10.0
    timeout_s: float = 10.0

    @classmethod
    def from_env(cls) -> "SplunkConfig | None":
        url = os.environ.get("SPLUNK_HEC_URL")
        token = os.environ.get("SPLUNK_HEC_TOKEN")
        if not url or not token:
            return None
        return cls(
            url=url.rstrip("/"),
            token=token,
            index=os.environ.get("SPLUNK_HEC_INDEX") or None,
            sourcetype=os.environ.get("SPLUNK_HEC_SOURCETYPE", "kong:guardrail:evaluation"),
            source=os.environ.get("SPLUNK_HEC_SOURCE", "guardrail-evaluator"),
            verify_tls=os.environ.get("SPLUNK_HEC_VERIFY_TLS", "true").lower() != "false",
            ca_file=os.environ.get("SPLUNK_HEC_CA_FILE") or None,
            use_ack=os.environ.get("SPLUNK_HEC_ACK", "false").lower() == "true",
        )


def envelope(cfg: SplunkConfig, event: dict) -> dict:
    ts = event.get("ts") or event.get("started_at_ms")
    t = (ts / 1000.0) if isinstance(ts, (int, float)) and ts > 1e11 else time.time()
    env = {"time": round(t, 3), "host": cfg.host, "source": cfg.source, "sourcetype": cfg.sourcetype, "event": event}
    if cfg.index:
        env["index"] = cfg.index
    return env


class SplunkHEC:
    def __init__(self, cfg: SplunkConfig):
        self.cfg = cfg
        self.channel = str(uuid.uuid4())
        self._ctx = None
        if cfg.url.startswith("https://"):
            self._ctx = ssl.create_default_context(cafile=cfg.ca_file)
            if not cfg.verify_tls:
                self._ctx.check_hostname = False
                self._ctx.verify_mode = ssl.CERT_NONE

    def _post(self, path: str, body: bytes, extra_headers: dict | None = None) -> tuple[int, dict | str]:
        req = urllib.request.Request(self.cfg.url + path, data=body, method="POST")
        req.add_header("Authorization", f"Splunk {self.cfg.token}")
        req.add_header("Content-Type", "application/json")
        if self.cfg.use_ack:
            req.add_header("X-Splunk-Request-Channel", self.channel)
        for k, v in (extra_headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout_s, context=self._ctx) as resp:
                raw = resp.read()
                try:
                    return resp.status, json.loads(raw.decode() or "{}")
                except Exception:  # noqa: BLE001
                    return resp.status, raw.decode(errors="replace")
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw.decode() or "{}")
            except Exception:  # noqa: BLE001
                return e.code, raw.decode(errors="replace")

    def send(self, events: list[dict]) -> tuple[bool, str]:
        """Send a batch (newline-delimited HEC envelopes). Returns (ok, detail)."""
        body = "\n".join(json.dumps(envelope(self.cfg, e), separators=(",", ":")) for e in events).encode()
        status, parsed = self._post("/services/collector/event", body)
        if status != 200 or not isinstance(parsed, dict) or parsed.get("code") != 0:
            return False, f"hec status={status} body={json.dumps(parsed)[:300]}"
        if self.cfg.use_ack and "ackId" in parsed:
            ok, detail = self._wait_ack(parsed["ackId"])
            if not ok:
                return False, f"hec accepted (ackId={parsed['ackId']}) but not acknowledged: {detail}"
            return True, f"accepted and acked ackId={parsed['ackId']}"
        return True, "accepted (HEC code 0); indexing/search visibility not verified by acceptance"

    def _wait_ack(self, ack_id: int) -> tuple[bool, str]:
        deadline = time.time() + self.cfg.ack_timeout_s
        while time.time() < deadline:
            status, parsed = self._post("/services/collector/ack", json.dumps({"acks": [ack_id]}).encode())
            if status == 200 and isinstance(parsed, dict) and (parsed.get("acks") or {}).get(str(ack_id)) is True:
                return True, "acked"
            time.sleep(0.5)
        return False, "ack timeout"

    def health(self) -> tuple[bool, str]:
        """GET /services/collector/health -> 200 {"text":"HEC is healthy","code":17} (no auth required)."""
        req = urllib.request.Request(self.cfg.url + "/services/collector/health", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout_s, context=self._ctx) as resp:
                return resp.status == 200, f"status={resp.status} body={resp.read().decode(errors='replace')[:200]}"
        except urllib.error.HTTPError as e:
            return False, f"status={e.code} body={e.read().decode(errors='replace')[:200]}"
        except Exception as e:  # noqa: BLE001
            return False, f"error={e}"
