"""OTLP/HTTP (JSON) logs exporter -> Grafana Alloy -> Loki.

Loki can only turn *resource* attributes into index labels, so events are
grouped by their low-cardinality label set and each group becomes one
ResourceLogs entry. High-cardinality identifiers (run_id, case_id,
request_id, ...) stay inside the log body as structured fields.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

LABEL_KEYS = ("event_type", "environment", "route", "guardrail", "stage", "outcome", "category", "policy_version", "synthetic")


@dataclass
class OtlpConfig:
    endpoint: str                      # e.g. http://alloy:4318/v1/logs
    headers: dict = field(default_factory=dict)
    service_name: str = "guardrail-evaluator"
    timeout_s: float = 10.0

    @classmethod
    def from_env(cls) -> "OtlpConfig | None":
        ep = os.environ.get("OTLP_LOGS_ENDPOINT")
        if not ep:
            return None
        headers = {}
        raw = os.environ.get("OTLP_HEADERS", "")  # "k1=v1,k2=v2" (Grafana Cloud: Authorization=Basic ...)
        for kv in [x for x in raw.split(",") if "=" in x]:
            k, v = kv.split("=", 1)
            headers[k.strip()] = v.strip()
        return cls(endpoint=ep, headers=headers, service_name=os.environ.get("OTEL_SERVICE_NAME", "guardrail-evaluator"))


def _attr(k: str, v) -> dict:
    if isinstance(v, bool):
        return {"key": k, "value": {"boolValue": v}}
    if isinstance(v, int):
        return {"key": k, "value": {"intValue": str(v)}}
    if isinstance(v, float):
        return {"key": k, "value": {"doubleValue": v}}
    return {"key": k, "value": {"stringValue": str(v)}}


def outcome_of(ev: dict) -> str:
    if ev.get("event_type") == "adjudication":
        return (ev.get("detector") or {}).get("outcome", "unknown")
    if ev.get("event_type") == "kong_observation":
        g = ev.get("guardrails") or []
        return g[-1].get("verdict", "none") if g else "none"
    return ev.get("outcome", "n/a")


def label_set(ev: dict) -> dict:
    labels = {"service.name": "guardrail-evaluator"}
    for k in LABEL_KEYS:
        v = ev.get(k)
        if k == "outcome":
            v = outcome_of(ev)
        if k == "route" and isinstance(v, dict):
            v = v.get("name") or v.get("id")
        if v is None:
            continue
        labels[k] = str(v).lower() if isinstance(v, bool) else str(v)
    return labels


def to_otlp(events: list[dict], cfg: OtlpConfig) -> dict:
    groups: dict[str, list[dict]] = {}
    label_by_key: dict[str, dict] = {}
    for ev in events:
        labels = label_set(ev)
        labels["service.name"] = cfg.service_name
        key = json.dumps(labels, sort_keys=True)
        groups.setdefault(key, []).append(ev)
        label_by_key[key] = labels
    resource_logs = []
    for key, evs in groups.items():
        labels = label_by_key[key]
        records = []
        for ev in evs:
            ts_ms = ev.get("ts") or ev.get("started_at_ms") or int(time.time() * 1000)
            severity = "WARN" if outcome_of(ev) in ("FP", "FN", "ENFORCEMENT_FAILURE") else "INFO"
            records.append({
                "timeUnixNano": str(int(ts_ms) * 1_000_000),
                "severityText": severity,
                "body": {"stringValue": json.dumps(ev, separators=(",", ":"))},
                "attributes": [_attr("event_id", ev.get("event_id")), _attr("run_id", ev.get("run_id")),
                               _attr("case_id", ev.get("case_id")), _attr("request_id", ev.get("request_id")),
                               _attr("schema_version", ev.get("schema_version"))],
            })
        resource_logs.append({
            "resource": {"attributes": [_attr(k, v) for k, v in labels.items()]},
            "scopeLogs": [{"scope": {"name": "guardrail-evaluator"}, "logRecords": records}],
        })
    return {"resourceLogs": resource_logs}


class OtlpLogs:
    def __init__(self, cfg: OtlpConfig):
        self.cfg = cfg

    def send(self, events: list[dict]) -> tuple[bool, str]:
        body = json.dumps(to_otlp(events, self.cfg)).encode()
        req = urllib.request.Request(self.cfg.endpoint, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        for k, v in self.cfg.headers.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout_s) as resp:
                raw = resp.read().decode(errors="replace")
                if resp.status in (200, 202):
                    # partial success is reported in the body per OTLP spec
                    try:
                        ps = json.loads(raw or "{}").get("partialSuccess") or {}
                        if ps.get("rejectedLogRecords"):
                            return False, f"otlp partial success: {ps}"
                    except Exception:  # noqa: BLE001
                        pass
                    return True, f"otlp status={resp.status}"
                return False, f"otlp status={resp.status} body={raw[:200]}"
        except urllib.error.HTTPError as e:
            return False, f"otlp status={e.code} body={e.read().decode(errors='replace')[:200]}"
        except Exception as e:  # noqa: BLE001
            return False, f"otlp error={e}"
