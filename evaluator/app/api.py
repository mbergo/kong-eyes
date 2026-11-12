"""The dashboard's own API. Everything the in-house dashboard shows comes from here and from the collector's
store; no Grafana, Loki or Prometheus is involved.

  GET /dashboard            the page
  GET /api/overview         the numbers for one window: per route, per guardrail, things to look at, plain words
  GET /api/timeseries       what happened to requests over time, and how long the gateway took
  GET /api/requests         the latest requests, one by one (with the start of the prompt when that is switched on)
"""
from __future__ import annotations

import json
import os
import time

from fastapi import Request, APIRouter
from fastapi.responses import HTMLResponse

from . import passive

router = APIRouter()
store = None            # set by main.py
summary = None          # set by main.py: (window_s, route, include_runs) -> passive summary
latest_findings = None  # set by main.py: () -> dict | None
PROMPT_CHARS = int(os.environ.get("EXPORT_PROMPT_CHARS", "0") or 0)


def _window(window_s: float) -> float:
    """Between 10 seconds and 24 hours; anything else falls back to five minutes."""
    return window_s if 10 <= window_s <= 86400 else 300.0


def _pct(a: float, b: float) -> float:
    return round(a / b, 4) if b else 0.0


def _plain(route: str, r: dict, guards: list[dict], window_s: float) -> list[str]:
    """A few sentences a person who has never seen Kong can read."""
    span = f"{round(window_s / 60)} minutes" if window_s >= 120 else f"{round(window_s)} seconds"
    n = r.get("requests") or 0
    if not n:
        return [f"No requests reached {route} in the last {span}."]
    out = [f"In the last {span}, {n:,} requests came in on {route}. {n - (r.get('blocked') or 0):,} reached the model and "
           f"{r.get('blocked') or 0:,} were stopped at the gateway."]
    for g in guards:
        if not g["reached"]:
            continue
        s = f"{g['name']} looked at {g['reached']:,} of them and stopped {g['stopped']:,} ({g['stopped_share']:.0%})."
        if g["fail_open"]:
            s += f" {g['fail_open']:,} waited for about its time limit and were then let through, so they may not have been checked."
        out.append(s)
    return out


@router.get("/api/overview")
def overview(window_s: float = 300, route: str | None = None):
    window_s = _window(window_s)
    s = summary(window_s, None, False)
    routes = []
    for name, r in sorted(s["routes"].items(), key=lambda kv: -kv[1].get("requests", 0)):
        routes.append({"name": name, "requests": r.get("requests", 0), "stopped": r.get("blocked", 0), "ai": r.get("ai_route", False),
                       "guardrails": r.get("guardrails_enabled", [])})
    chosen = route if route in s["routes"] else next((x["name"] for x in routes if x["ai"] and x["guardrails"]), routes[0]["name"] if routes else None)
    if chosen:                                             # the guardrail numbers and the patterns are for this route only
        s = summary(window_s, chosen, False)
    r = s["routes"].get(chosen) or {}
    order = [c["name"] for c in r.get("chain", []) if c["kind"] in ("guardrail", "candidate")]
    labels = {c["name"]: c.get("label") or c["name"] for c in r.get("chain", [])}
    guards = []
    for name in order:
        g = s["guardrails"].get(name)
        if not g:
            continue
        reached = g.get("reached") or 0
        stopped = g.get("blocked") or 0                    # only what ended the request; a redaction lets it continue
        lat = g.get("latency_ms") or {}
        ab = (s.get("after_block") or {}).get(name) or {}
        guards.append({"name": name, "label": labels.get(name, name), "reached": reached, "stopped": stopped, "stopped_share": _pct(stopped, reached),
                       "time_ms": {"median": lat.get("p50"), "p95": lat.get("p95"), "max": lat.get("max")}, "timeout_ms": g.get("timeout_ms"),
                       "fail_open": g.get("fail_open_suspects") or 0, "no_decision": g.get("no_verdict") or 0,
                       "flagged_but_served": g.get("detected_not_enforced") or 0,
                       "rewrites": (g.get("request_rewrites") or 0) + (g.get("response_rewrites") or 0) + (g.get("enforced_inline") or 0),
                       "retries_after_stop": ab.get("followed_by_retry") or 0, "retries_got_through": ab.get("retry_got_through") or 0,
                       "exact_timing": not g.get("latency_shared_gap_requests")})
    signals = [{"kind": x.get("kind"), "severity": x.get("severity"), "guardrail": x.get("guardrail"), "route": x.get("route"), "summary": x.get("summary")}
               for x in s.get("signals", []) if not x.get("route") or x.get("route") == chosen]
    f = latest_findings() if latest_findings else None
    n, stopped = r.get("requests", 0), r.get("blocked", 0)
    elsewhere = max(0, stopped - sum(g["stopped"] for g in guards))      # auth, rate limits, anything that is not a guardrail
    return {"generated_at_ms": int(time.time() * 1000), "window_s": window_s, "route": chosen, "routes": routes,
            "totals": {"requests": n, "served": n - stopped, "stopped": stopped, "stopped_share": _pct(stopped, n),
                       "waited": sum(g["fail_open"] for g in guards), "stopped_elsewhere": elsewhere,
                       "gateway_ms": r.get("duration_ms") or {}, "guardrail_share_of_time": r.get("chain_share_p50")},
            "chain": [{"name": c["name"], "label": c.get("label") or c["name"], "kind": c["kind"]} for c in r.get("chain", [])
                      if c["kind"] in ("guardrail", "candidate", "router")],
            "guardrails": guards, "signals": signals, "plain": _plain(chosen or "this gateway", r, guards, window_s),
            "findings": ({"headline": f.get("headline"), "items": f.get("findings") or [], "provider": f.get("provider"),
                          "generated_at_ms": f.get("generated_at_ms")} if f else None),
            "prompts_on": PROMPT_CHARS > 0}


@router.get("/api/timeseries")
def timeseries(window_s: float = 300, buckets: int = 60, route: str | None = None):
    window_s = _window(window_s)
    buckets = max(10, min(240, buckets))
    now = int(time.time() * 1000)
    step = max(1000, int(window_s * 1000 / buckets))
    start = (now - int(window_s * 1000)) // step * step
    where, params = "started_at_ms >= ? AND started_at_ms <= ? AND run_id IS NULL", [start, now + step]
    if route:
        where += " AND route = ?"; params.append(route)
    rows = store.q(f"SELECT (started_at_ms - ?) / ? AS b, COALESCE(result, 'unknown') AS result, COUNT(*) AS n FROM kong_observations "
                   f"WHERE {where} GROUP BY b, result", [start, step] + params)
    n_buckets = (now - start) // step + 1
    series: dict[str, list[int]] = {}
    for r in rows:
        if 0 <= r["b"] < n_buckets:
            series.setdefault(r["result"], [0] * n_buckets)[r["b"]] = r["n"]
    total = store.q1(f"SELECT COUNT(*) AS n FROM kong_observations WHERE {where}", params)["n"]
    every = max(1, total // 40000)                        # percentiles from at most ~40k rows
    lat = store.q(f"SELECT (started_at_ms - ?) / ? AS b, duration_ms AS d, guard_ms AS g FROM kong_observations WHERE {where} AND duration_ms IS NOT NULL"
                  + (f" AND rowid % {every} = 0" if every > 1 else ""), [start, step] + params)
    per: list[list[int]] = [[] for _ in range(n_buckets)]
    gper: list[list[int]] = [[] for _ in range(n_buckets)]
    for r in lat:
        if 0 <= r["b"] < n_buckets:
            per[r["b"]].append(r["d"])
            if r["g"] is not None:
                gper[r["b"]].append(r["g"])

    def q(xs, p):
        return passive.quantile(xs, p) if xs else None
    order = sorted(series, key=lambda k: (k != "served", not k.startswith("stopped"), k))
    return {"start_ms": start, "step_ms": step, "buckets": n_buckets, "sampled_every": every,
            "outcomes": [{"name": k, "values": series[k]} for k in order],
            "gateway_ms": {"median": [q(x, 0.5) for x in per], "p95": [q(x, 0.95) for x in per]},
            "guardrail_ms": {"p95": [q(x, 0.95) for x in gper]}}


@router.get("/api/requests")
def requests(limit: int = 100, route: str | None = None, result: str | None = None):
    limit = max(1, min(500, limit))
    where, params = "run_id IS NULL", []
    if route:
        where += " AND route = ?"; params.append(route)
    if result == "stopped":
        where += " AND result LIKE 'stopped%'"
    elif result == "waited":
        where += " AND result LIKE 'waited%'"
    elif result == "served":
        where += " AND result = 'served'"
    rows = store.q(f"SELECT payload FROM kong_observations WHERE {where} ORDER BY started_at_ms DESC LIMIT ?", params + [limit])
    out = []
    for row in rows:
        g = json.loads(row["payload"])
        a = passive.apm_view(g)
        req = g.get("request") or {}
        prompt = None
        if PROMPT_CHARS > 0 and req.get("body_prefix"):
            prompt = passive.prompt_excerpt(req["body_prefix"], PROMPT_CHARS)
        c = g.get("consumer") or {}
        out.append({"at_ms": g.get("started_at_ms"), "status": (g.get("response") or {}).get("status"), "result": a["result"], "stopped_by": a["stopped_by"],
                    "total_ms": g.get("duration_ms"), "steps": a["steps"], "route": (g.get("route") or {}).get("name"),
                    "caller": c.get("username") if isinstance(c, dict) else None, "prompt": prompt, "id": g.get("request_id")})
    return {"requests": out, "prompts_on": PROMPT_CHARS > 0}


@router.get("/api/connect")
def connect_info(request: Request):
    """What a Kong needs to report here. Only reachable behind the front-door login on public installs."""
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "localhost"
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    return {"ingest_url": f"{proto}://{host}/ingest/kong", "ingest_token": os.environ.get("INGEST_TOKEN", "")}


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    with open(os.path.join(os.path.dirname(__file__), "static", "dashboard.html"), encoding="utf-8") as f:
        return HTMLResponse(f.read())
