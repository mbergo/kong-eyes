"""Which gateways are sending data here: address, the name that address resolves to, routes, and when they last spoke.

Kept in memory and rebuilt from the next events after a restart; it is a "who is connected right now" view, not history.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time

from fastapi import APIRouter, Request

router = APIRouter()
SEEN: dict[str, dict] = {}
MAX_GATEWAYS = 200


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
        SEEN[ip]["name"] = await asyncio.wait_for(asyncio.to_thread(_resolve, ip), timeout=5)
    except (asyncio.TimeoutError, KeyError):
        pass


def note(request: Request, events: int, routes: set[str], environments: set[str], versions: set[str]) -> None:
    ip, now = _address(request), time.time()
    g = SEEN.get(ip)
    if g is None:
        if len(SEEN) >= MAX_GATEWAYS:
            SEEN.pop(min(SEEN, key=lambda k: SEEN[k]["last_seen"]))
        g = SEEN[ip] = {"address": ip, "name": None, "first_seen": now, "last_seen": now, "events": 0, "routes": set(), "environments": set(),
                        "kong_versions": set(), "local": _is_local(ip)}
        asyncio.get_running_loop().create_task(_name(ip))
    g["last_seen"] = now; g["events"] += events
    g["routes"] |= {r for r in routes if r}; g["environments"] |= {e for e in environments if e}; g["kong_versions"] |= {v for v in versions if v}


def _is_local(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback
    except ValueError:
        return False


@router.get("/api/gateways")
def gateways():
    now = time.time()
    rows = [{"address": g["address"], "name": g["name"], "on_this_server": g["local"], "first_seen_ms": int(g["first_seen"] * 1000),
             "last_seen_ms": int(g["last_seen"] * 1000), "seconds_since_last": round(now - g["last_seen"], 1), "sending": now - g["last_seen"] < 60,
             "events": g["events"], "routes": sorted(g["routes"]), "environments": sorted(g["environments"]), "kong_versions": sorted(g["kong_versions"])}
            for g in sorted(SEEN.values(), key=lambda g: -g["last_seen"])]
    return {"generated_at_ms": int(now * 1000), "gateways": rows}
