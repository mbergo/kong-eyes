"""Demo console: a separate page with knobs for the synthetic stand-in guardrails and the mock traffic.

Off unless DEMO_CONSOLE=true. It is for the bundled demo stack only:
  * it changes plugin config through Kong's Admin API (DB-less: read /config, edit, post it back), and only
    touches plugins on DEMO_ROUTE that are stand-ins (their config has the fixture's `miss_rate` field) plus that
    route's observer; nothing else in the gateway is edited;
  * changes live in Kong's memory: restarting Kong returns to what the declarative file says;
  * it has no login of its own. Keep it on localhost, or behind a login: deploy/Caddyfile serves it at
    /eyes/demo only to a browser already logged in to Grafana.
Never enable it on an evaluator that can reach a real gateway's Admin API.
"""
from __future__ import annotations

import asyncio
import collections
import json
import os
import random
import time

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

ENABLED = os.environ.get("DEMO_CONSOLE", "false").lower() == "true"
ADMIN = os.environ.get("DEMO_KONG_ADMIN_URL", "http://kong:8001").rstrip("/")
PROXY = os.environ.get("DEMO_KONG_PROXY_URL", "http://kong:8000").rstrip("/")
ROUTE = os.environ.get("DEMO_ROUTE", "ai-named-route")
PATH = os.environ.get("DEMO_PATH", "/ai/named")
MAX_MIN = float(os.environ.get("DEMO_TRAFFIC_MAX_MIN", "30") or 30)   # traffic stops by itself after this long

router = APIRouter()
translate_now = None          # set by main.py: an async callable that refreshes the plain-language findings
_lock = asyncio.Lock()


def _need():
    if not ENABLED:
        raise HTTPException(404, "demo console is off (DEMO_CONSOLE=true turns it on)")


# ----------------------------------------------------------------------------- Kong config
async def _load() -> dict:
    import yaml
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.get(ADMIN + "/config")
    r.raise_for_status()
    return yaml.safe_load(r.json()["config"])


async def _save(cfg: dict) -> None:
    import yaml
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post(ADMIN + "/config?check_hash=0", json={"config": yaml.safe_dump(cfg)})
    if r.status_code >= 300:
        raise HTTPException(502, f"Kong rejected the config: {r.text[:300]}")


def _route_plugins(cfg: dict) -> tuple[list[dict], dict | None]:
    rid = next((r["id"] for r in cfg.get("routes", []) if r.get("name") == ROUTE), None)
    if not rid:
        raise HTTPException(409, f"route {ROUTE} is not on this gateway: run scripts/gen-demo-guards.sh first")
    mine = [p for p in cfg.get("plugins", []) if p.get("route") == rid]
    guards = sorted((p for p in mine if "miss_rate" in (p.get("config") or {})), key=lambda p: p["name"])
    observer = next((p for p in mine if p["name"] == "guardrail-observer"), None)
    return guards, observer


def _guard_view(p: dict) -> dict:
    c = p["config"]
    return {"name": p["name"], "miss_rate": c.get("miss_rate") or 0, "overcatch_ratio": c.get("overcatch_ratio") or 0,
            "slow_ms": c.get("slow_ms") or 400, "fails_open": bool(c.get("slow_markers")), "mode": c.get("mode", "block")}


# ----------------------------------------------------------------------------- traffic
BENIGN = ["Summarise the attached meeting notes.", "Draft a polite reply to this customer.", "Explain this stack trace.",
          "Translate the paragraph to Portuguese.", "List three risks in this plan.", "Write release notes for the new build.",
          "Rewrite this for a non-technical reader.", "Give three alternatives to a nightly cron job."]
T = {"running": False, "rps": 4.0, "violation": 6, "obfuscated": 4, "slow": 0, "wave_until": 0.0,
     "sent": 0, "status": collections.Counter(), "started": 0.0, "error": None, "note": None}
_task: asyncio.Task | None = None


def _pick() -> tuple[str, str]:
    wave = time.time() < T["wave_until"]
    w = {"violation": T["violation"] * (5 if wave else 1), "obfuscated": T["obfuscated"] * (5 if wave else 1), "slow": T["slow"]}
    w["benign"] = max(5.0, 100 - sum(w.values()))
    kind = random.choices(list(w), list(w.values()))[0]
    b = random.choice(BENIGN)
    text = {"benign": f"{b} respond:CLEAN", "violation": f"{b} [[VIOLATION]]", "obfuscated": f"{b} [[VI0LATION]] respond:CLEAN",
            "slow": f"[[FIXTURE_SLOW]] {b} respond:CLEAN"}[kind]
    return kind, text


async def _traffic():
    keys = {"runner": os.environ.get("RUNNER_APIKEY", ""), "untrusted-client": "untrusted-client-key"}
    retry: list[str] = []
    async with httpx.AsyncClient(timeout=30) as c:
        async def one(kind: str, text: str, who: str):
            try:
                r = await c.post(PROXY + PATH, headers={"apikey": keys[who]},
                                 json={"model": "mock-gpt", "messages": [{"role": "user", "content": text}]})
                T["status"][str(r.status_code)] += 1
                if kind == "benign" and r.status_code == 403:
                    retry.append(who)                       # an honest caller blocked by mistake tries again
            except Exception as e:  # noqa: BLE001
                T["status"]["error"] += 1; T["error"] = type(e).__name__
        while T["running"]:
            if time.time() - T["started"] > MAX_MIN * 60:
                T.update(running=False, note=f"stopped by itself after {MAX_MIN:g} min; press Start for more")
                break
            kind, text = _pick()
            who = "untrusted-client" if kind in ("violation", "obfuscated") and random.random() < 0.7 else "runner"
            if retry and random.random() < 0.6:
                who, kind, text = retry.pop(0), "benign", f"{random.choice(BENIGN)} respond:CLEAN"
            asyncio.create_task(one(kind, text, who)); T["sent"] += 1
            await asyncio.sleep(random.expovariate(max(0.2, min(40.0, T["rps"]))))


def _traffic_view() -> dict:
    return {"running": T["running"], "rps": T["rps"], "violation": T["violation"], "obfuscated": T["obfuscated"], "slow": T["slow"],
            "wave_seconds_left": max(0, int(T["wave_until"] - time.time())), "sent": T["sent"], "status": dict(T["status"]),
            "error": T["error"], "note": T["note"],
            "minutes_left": max(0, round(MAX_MIN - (time.time() - T["started"]) / 60)) if T["running"] else 0}


# ----------------------------------------------------------------------------- endpoints
@router.get("/demo", response_class=HTMLResponse)
async def demo_page():
    _need()
    with open(os.path.join(os.path.dirname(__file__), "static", "demo.html"), encoding="utf-8") as f:
        return HTMLResponse(f.read())


@router.get("/demo/state")
async def demo_state():
    _need()
    try:
        guards, observer = _route_plugins(await _load())
        kong = {"ok": True}
    except HTTPException as e:
        guards, observer, kong = [], None, {"ok": False, "error": e.detail}
    except Exception as e:  # noqa: BLE001
        guards, observer, kong = [], None, {"ok": False, "error": f"cannot reach Kong's Admin API at {ADMIN}: {type(e).__name__}"}
    return {"route": ROUTE, "path": PATH, "kong": kong, "guards": [_guard_view(p) for p in guards],
            "show_prompts": bool(observer and (observer.get("config") or {}).get("capture_body_mode") == "bounded"),
            "prompts_exported": int(os.environ.get("EXPORT_PROMPT_CHARS", "0") or 0) > 0,
            "traffic": _traffic_view(), "grafana_url": os.environ.get("DEMO_GRAFANA_URL", ""),
            "translator": os.environ.get("TRANSLATE_PROVIDER") or "auto"}


@router.post("/demo/guard/{name}")
async def demo_guard(name: str, body: dict):
    _need()
    async with _lock:
        cfg = await _load(); guards, observer = _route_plugins(cfg)
        g = next((p for p in guards if p["name"] == name), None)
        if not g:
            raise HTTPException(404, f"{name} is not a stand-in guardrail on {ROUTE}")
        c = g["config"]
        if "miss_rate" in body:
            c["miss_rate"] = min(1.0, max(0.0, float(body["miss_rate"])))
        if "overcatch_ratio" in body:
            c["overcatch_ratio"] = min(3.0, max(0.0, float(body["overcatch_ratio"])))
        if "fails_open" in body:
            c["slow_markers"] = ["[[FIXTURE_SLOW]]"] if body["fails_open"] else []
        if "slow_ms" in body:
            c["slow_ms"] = int(min(5000, max(50, float(body["slow_ms"]))))
        if "mode" in body and body["mode"] in ("block", "detect", "disabled"):
            c["mode"] = body["mode"]
        if observer is not None:                              # the fail-open check compares against this timeout
            t = dict((observer["config"].get("guardrail_timeouts") or {}))
            if c.get("slow_markers"):
                t[name] = c.get("slow_ms") or 400
            else:
                t.pop(name, None)
            observer["config"]["guardrail_timeouts"] = t or None
        await _save(cfg)
        return _guard_view(g)


@router.post("/demo/prompts")
async def demo_prompts(body: dict):
    _need()
    async with _lock:
        cfg = await _load(); _, observer = _route_plugins(cfg)
        if observer is None:
            raise HTTPException(409, "no observer on the demo route")
        observer["config"]["capture_body_mode"] = "bounded" if body.get("on") else "hash"
        await _save(cfg)
        return {"show_prompts": bool(body.get("on"))}


@router.post("/demo/traffic")
async def demo_traffic(body: dict):
    _need()
    global _task
    for k in ("rps", "violation", "obfuscated", "slow"):
        if k in body:
            T[k] = max(0.0, min(40.0 if k == "rps" else 60.0, float(body[k])))
    if body.get("wave"):
        T["wave_until"] = time.time() + 60
    if "running" in body:
        if body["running"] and not T["running"]:
            T.update(running=True, started=time.time(), error=None, note=None)
            _task = asyncio.create_task(_traffic())
        elif not body["running"]:
            T["running"] = False
    return _traffic_view()


@router.post("/demo/translate")
async def demo_translate():
    _need()
    if translate_now is None:
        raise HTTPException(503, "translator not wired")
    doc = await translate_now()
    return {"headline": doc.get("headline"), "provider": doc.get("provider"), "error": doc.get("error")}
