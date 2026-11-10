"""Normalize what Kong's http-log plugin actually sends.

http-log posts either a single JSON object (queue.max_batch_size == 1) or a JSON
array of objects (max_batch_size > 1). Each object is kong.log.serialize()
output, enriched by the observer under <namespace> (default guardrail_observer)
and by the tail plugin under <namespace>.tail. Vendor plugins may add their own
keys (ai.proxy.*, guardrail_fixture.*). We normalize here, never in Lua.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

MAX_EVENT_BYTES = 4 * 1024 * 1024


class IngestError(Exception):
    pass


def parse_body(raw: bytes) -> list[dict]:
    if len(raw) > 64 * 1024 * 1024:
        raise IngestError("payload too large")
    try:
        # never let a stray byte in one event poison a whole http-log batch (Kong would retry it forever)
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001
        raise IngestError(f"invalid json: {e}") from e
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list) and all(isinstance(x, dict) for x in data):
        return data
    raise IngestError("expected object or array of objects")


def extract_observer(event: dict, namespace: str) -> dict | None:
    gro = event.get(namespace)
    if not isinstance(gro, dict) or not gro.get("event_id"):
        return None
    # merge the tail snapshot (set from body_filter, so it lands as a sibling key)
    tail = gro.get("tail")
    if tail is None and isinstance(event.get(namespace), dict):
        tail = event[namespace].get("tail")
    # native Kong fields worth carrying along (low volume, high value)
    native = {
        "request_id": (event.get("request") or {}).get("id"),
        "client_ip": event.get("client_ip"),
        "started_at": event.get("started_at"),
        "latencies": event.get("latencies"),
        "upstream_status": event.get("upstream_status"),
        "response_size": (event.get("response") or {}).get("size"),
        "tries": event.get("tries"),
        "route_id": (event.get("route") or {}).get("id"),
        "service_id": (event.get("service") or {}).get("id"),
        "consumer_id": (event.get("consumer") or {}).get("id"),
        "workspace": event.get("workspace_name"),
    }
    gro = dict(gro)
    gro["native"] = native
    gro["tail"] = tail
    ai = event.get("ai")
    if isinstance(ai, dict):
        gro["ai_native"] = _scrub_ai(ai)
    fx = event.get("guardrail_fixture")
    if isinstance(fx, dict):
        gro["guardrail_fixture_native"] = fx
    if not gro.get("request_id"):
        gro["request_id"] = native["request_id"]
    return gro


def _scrub_ai(ai: dict) -> dict:
    """Keep ai.<plugin>.meta/usage; drop payloads unless they are already bounded (we never re-export prompts)."""
    out = {}
    for plugin, v in ai.items():
        if not isinstance(v, dict):
            continue
        out[plugin] = {k: val for k, val in v.items() if k in ("meta", "usage")}
        if "payload" in v:
            out[plugin]["payload_present"] = True
    return out


def body_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
