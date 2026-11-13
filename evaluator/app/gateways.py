"""Which gateways are sending data here, one entry per gateway: its name, the nodes it sends from (address and the
name that address resolves to), its routes, and the models seen behind each route.

A gateway is named by the `gateway` field `koe connect` stamps on its events (for Konnect, the control plane's name).
Events without one are grouped by where they come from. Kept in memory and rebuilt from the next events after a
restart: this is a "who is connected right now" view, not history.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time

from fastapi import APIRouter, Request

router = APIRouter()
SEEN: dict[str, dict] = {}        # gateway name -> gateway
NAMES: dict[str, str | None] = {}  # address -> resolved name
MAX_GATEWAYS, MAX_NODES = 200, 50


def _address(request: Request) -> str:
    """The sender's address. A forwarded address is only believed when the request came through our own proxy."""
    if "x-front-door" in request.headers:
        first = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        try:
            return str(ipaddress.ip_address(first))
        except ValueError:
            pass
    return request.client.host if request.client else "unknown"


def _resolve(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None


async def _name(ip: str) -> None:
    try:
        NAMES[ip] = await asyncio.wait_for(asyncio.to_thread(_resolve, ip), timeout=5)
    except asyncio.TimeoutError:
        pass


def _is_local(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback
    except ValueError:
        return False


def model_of(gro: dict) -> str | None:
    """The model a request went to, from Kong's own AI fields when the request reached one."""
    for v in (gro.get("ai_native") or {}).values():
        meta = (v or {}).get("meta") or {}
        for m in (meta.get("response_model"), meta.get("request_model")):
            if m and str(m).upper() != "UNSPECIFIED":          # Kong writes UNSPECIFIED when the request never reached a model
                return str(m)
    m = (gro.get("request") or {}).get("model")
    return str(m) if m and str(m).upper() != "UNSPECIFIED" else None


def note(request: Request, events: list[dict]) -> None:
    """events: one dict per accepted event with route, environment, kong_version, gateway, model."""
    if not events:
        return
    ip, now = _address(request), time.time()
    if ip not in NAMES:
        NAMES[ip] = None
        asyncio.get_running_loop().create_task(_name(ip))
    local = _is_local(ip)
    for e in events:
        key = e.get("gateway") or ("Demo Kong on this server" if local else ip)
        g = SEEN.get(key)
        if g is None:
            if len(SEEN) >= MAX_GATEWAYS:
                SEEN.pop(min(SEEN, key=lambda k: SEEN[k]["last_seen"]))
            g = SEEN[key] = {"name": key, "named": bool(e.get("gateway")), "first_seen": now, "last_seen": now, "events": 0, "nodes": {}, "routes": {},
                             "environments": set(), "kong_versions": set(), "local": local}
        g["last_seen"] = now; g["events"] += 1
        if e.get("environment"):
            g["environments"].add(str(e["environment"]))
        if e.get("kong_version"):
            g["kong_versions"].add(str(e["kong_version"]))
        if ip in g["nodes"] or len(g["nodes"]) < MAX_NODES:
            node = g["nodes"].setdefault(ip, {"first_seen": now, "last_seen": now, "events": 0})
            node["last_seen"] = now; node["events"] += 1
        if e.get("route"):
            r = g["routes"].setdefault(str(e["route"]), {"events": 0, "last_seen": now, "models": {}})
            r["events"] += 1; r["last_seen"] = now
            if e.get("model"):
                r["models"][e["model"]] = r["models"].get(e["model"], 0) + 1


@router.get("/api/gateways")
def gateways():
    now = time.time()
    out = []
    for g in sorted(SEEN.values(), key=lambda g: (-(now - g["last_seen"] < 60), g["name"].lower())):
        routes = [{"name": k, "events": r["events"], "seconds_since_last": round(now - r["last_seen"], 1),
                   "models": [m for m, _ in sorted(r["models"].items(), key=lambda kv: -kv[1])]} for k, r in sorted(g["routes"].items())]
        nodes = [{"address": ip, "name": NAMES.get(ip), "events": n["events"], "seconds_since_last": round(now - n["last_seen"], 1), "sending": now - n["last_seen"] < 60}
                 for ip, n in sorted(g["nodes"].items(), key=lambda kv: -kv[1]["last_seen"])]
        out.append({"name": g["name"], "named_by_gateway": g["named"], "on_this_server": g["local"], "sending": now - g["last_seen"] < 60,
                    "first_seen_ms": int(g["first_seen"] * 1000), "last_seen_ms": int(g["last_seen"] * 1000), "seconds_since_last": round(now - g["last_seen"], 1),
                    "events": g["events"], "environments": sorted(g["environments"]), "kong_versions": sorted(g["kong_versions"]),
                    "routes": routes, "models": sorted({m for r in routes for m in r["models"]}), "nodes": nodes})
    return {"generated_at_ms": int(now * 1000), "gateways": out}
