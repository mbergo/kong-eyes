"""Guardrail evaluation service.

Receives Kong http-log batches (enriched by guardrail-observer), runner
observations and labeled cases; joins and adjudicates; exposes Prometheus
metrics; exports observations + adjudications to Splunk HEC and/or OTLP->Loki
through independent durable queues.
"""
from __future__ import annotations

import asyncio
import base64
import csv
import io
import json
import logging
import os
import secrets
import time
import uuid

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from . import adjudicate as adj
from . import demo, ingest, metrics, passive, translate
from .exporters import metrics_hooks
from .exporters.otlp import OtlpConfig, OtlpLogs
from .exporters.splunk import SplunkConfig, SplunkHEC
from .exporters.worker import OutboxWorker
from .store import Store

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("evaluator")

DB_PATH = os.environ.get("EVAL_DB_PATH", "/data/evaluator.db")
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "")
RUNNER_TOKEN = os.environ.get("RUNNER_TOKEN", "")
NAMESPACE = os.environ.get("OBSERVER_NAMESPACE", "guardrail_observer")
JOIN_TIMEOUT_S = float(os.environ.get("JOIN_TIMEOUT_S", "120"))
EXPORT_OBSERVATIONS = os.environ.get("EXPORT_OBSERVATIONS", "true").lower() == "true"
VERSION = "0.2.0"
PASSIVE_WINDOW_S = float(os.environ.get("PASSIVE_WINDOW_S", "900"))

store = Store(DB_PATH)
metrics.register(store)
app = FastAPI(title="guardrail-evaluator", version=VERSION)

# Content never leaves the evaluator unless you ask for it twice: the route's observer must capture bodies
# (capture_body_mode: bounded) AND this must be > 0. Then the start of the last user message is exported
# with each observation so a dashboard can list prompts. Meant for synthetic traffic and test environments.
EXPORT_PROMPT_CHARS = int(os.environ.get("EXPORT_PROMPT_CHARS", "0") or 0)


def _prompt_excerpt(body_prefix: str, limit: int) -> str | None:
    """Last user message from a (possibly truncated) chat-completions body, cut to `limit` characters."""
    try:
        msgs = json.loads(body_prefix).get("messages") or []
        users = [m.get("content") for m in msgs if isinstance(m, dict) and m.get("role") == "user" and isinstance(m.get("content"), str)]
        text = users[-1] if users else None
    except Exception:
        i = body_prefix.rfind('"content":')            # body was cut mid-JSON: take what follows the last content key
        text = body_prefix[i + 10:].lstrip(' "') if i >= 0 else None
    if not text:
        return None
    text = " ".join(text.split())
    return text[:limit] + ("…" if len(text) > limit else "")

DESTINATIONS: dict[str, OutboxWorker] = {}


def _start_workers():
    splunk_cfg = SplunkConfig.from_env()
    if splunk_cfg:
        w = OutboxWorker(store, "splunk", SplunkHEC(splunk_cfg))
        DESTINATIONS["splunk"] = w
        w.start()
        log.info("splunk exporter -> %s index=%s sourcetype=%s ack=%s", splunk_cfg.url, splunk_cfg.index, splunk_cfg.sourcetype, splunk_cfg.use_ack)
    otlp_cfg = OtlpConfig.from_env()
    if otlp_cfg:
        w = OutboxWorker(store, "otlp", OtlpLogs(otlp_cfg))
        DESTINATIONS["otlp"] = w
        w.start()
        log.info("otlp logs exporter -> %s", otlp_cfg.endpoint)
    if not DESTINATIONS:
        log.warning("no export destination configured (SPLUNK_HEC_URL/TOKEN or OTLP_LOGS_ENDPOINT); results stay local")


_start_workers()


def _fanout(event: dict):
    for dest in DESTINATIONS:
        store.enqueue(dest, event["event_id"], event)


# ------------------------------------------------------------------- auth helpers
def _token_from(request: Request) -> str | None:
    h = request.headers.get("authorization", "")
    if h.lower().startswith("bearer "):
        return h[7:].strip()
    if h.lower().startswith("basic "):
        try:
            userinfo = base64.b64decode(h[6:].strip()).decode()
            return userinfo.split(":", 1)[1] if ":" in userinfo else userinfo
        except Exception:  # noqa: BLE001
            return None
    return None


def require_ingest_token(request: Request):
    if INGEST_TOKEN and not secrets.compare_digest(_token_from(request) or "", INGEST_TOKEN):
        store.log_ingest("kong", "unauthorized")
        metrics_hooks.ingest_result("kong", "unauthorized")
        raise HTTPException(401, "bad ingest token")


def require_runner_token(request: Request):
    if RUNNER_TOKEN and not secrets.compare_digest(_token_from(request) or "", RUNNER_TOKEN):
        raise HTTPException(401, "bad runner token")


# ----------------------------------------------------------------------- ingest
@app.post("/ingest/kong", dependencies=[Depends(require_ingest_token)])
async def ingest_kong(request: Request):
    raw = await request.body()
    try:
        events = ingest.parse_body(raw)
    except ingest.IngestError as e:
        store.log_ingest("kong", "rejected", str(e))
        metrics_hooks.ingest_result("kong", "rejected")
        raise HTTPException(400, str(e))
    accepted = dup = skipped = bad = 0
    for ev in events:
        try:
            gro = ingest.extract_observer(ev, NAMESPACE)
            if gro is None:
                skipped += 1  # a Kong log without the observer namespace: route not observed
                continue
            gro["ts"] = gro.get("started_at_ms")
            gro["route_name"] = (gro.get("route") or {}).get("name")
            if store.insert_kong_observation(gro, ev):
                accepted += 1
                if EXPORT_OBSERVATIONS:
                    _fanout(_observation_export_view(gro))
                metrics.GATEWAY_DURATION.labels(environment=str(gro.get("environment")), route=str(gro.get("route_name"))).observe(gro.get("duration_ms") or 0)
            else:
                dup += 1
        except Exception as e:  # noqa: BLE001
            bad += 1
            log.warning("malformed observation skipped: %s", e)
            store.log_ingest("kong", "rejected", str(e)[:200]); metrics_hooks.ingest_result("kong", "rejected")
    store.log_ingest("kong", "accepted", str(accepted))
    metrics_hooks.ingest_result("kong", "accepted", accepted)
    if dup:
        store.log_ingest("kong", "duplicate", str(dup)); metrics_hooks.ingest_result("kong", "duplicate", dup)
    if skipped:
        store.log_ingest("kong", "no_observer_namespace", str(skipped)); metrics_hooks.ingest_result("kong", "no_observer_namespace", skipped)
    # 200 only after durable local persistence (SQLite commit) - this is the ack http-log waits for
    return {"accepted": accepted, "duplicate": dup, "skipped_no_observer": skipped, "malformed": bad}


def _observation_export_view(gro: dict) -> dict:
    """Bounded view of a Kong observation for destinations (never body prefixes)."""
    v = {k: gro.get(k) for k in ("schema_version", "event_type", "event_id", "request_id", "environment", "policy_version",
                                 "policy_fingerprint", "started_at_ms", "ended_at_ms", "duration_ms", "kong_version",
                                 "observer_version", "guardrails", "exit", "upstream", "gaps", "attempts", "configured_plugins",
                                 "plugin_chain", "capture", "ai_native", "native", "trail", "guardrails_configured", "thresholds")}
    v["ts"] = gro.get("started_at_ms")
    v["route"] = (gro.get("route") or {}).get("name") or (gro.get("route") or {}).get("id")
    v["service"] = (gro.get("service") or {}).get("name")
    v["consumer"] = (gro.get("consumer") or {}).get("username")
    r = gro.get("runner") or {}
    v["runner"] = {k: r.get(k) for k in ("present", "trusted", "reason", "run_id", "case_id", "trial", "skew_ms")}
    v["run_id"], v["case_id"], v["trial"] = (r.get("run_id"), r.get("case_id"), r.get("trial")) if r.get("trusted") else (None, None, None)
    resp = gro.get("response") or {}
    v["response"] = {k: resp.get(k) for k in ("status", "source", "proxied", "upstream_status", "content_type")}
    req = gro.get("request") or {}
    v["request"] = {k: req.get(k) for k in ("method", "path", "body_bytes", "body_sha256", "stream_requested", "model", "message_count", "prompt_chars", "json_valid", "body_in_file")}
    if EXPORT_PROMPT_CHARS > 0 and req.get("body_prefix"):
        v["request"]["prompt_excerpt"] = _prompt_excerpt(req["body_prefix"], EXPORT_PROMPT_CHARS)
    for key in ("stream", "tail"):
        s = gro.get(key) or {}
        v[key] = {k: s.get(k) for k in ("chunks", "bytes", "sha256", "first_chunk_at_ms", "eof_at_ms", "truncated", "observed_at")} if s else None
    ai = gro.get("ai") or {}
    v["ai"] = {k: ai.get(k) for k in ("executed_filters", "stream_mode", "model", "response_body_bytes", "response_body_source", "metrics")} if ai else None
    gs = v.get("guardrails") or []
    v["guardrail"] = gs[-1].get("guardrail") if gs else None
    v["stage"] = gs[-1].get("stage") if gs else None
    return v


# ------------------------------------------------------------------------ runs
@app.post("/runs", dependencies=[Depends(require_runner_token)])
async def create_run(body: dict):
    run_id = body.get("run_id") or f"run-{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:6]}"
    mode = body.get("mode", "evaluate")
    if mode not in ("observe", "evaluate"):
        raise HTTPException(400, "mode must be observe|evaluate")
    cases = body.get("cases") or []
    if mode == "evaluate" and not cases:
        raise HTTPException(400, "evaluate mode requires labeled cases")
    for c in cases:
        if "case_id" not in c or "expected_action" not in c:
            raise HTTPException(400, f"case missing case_id/expected_action: {c}")
    manifest = body.get("manifest") or {}
    manifest.setdefault("expected_units", body.get("expected_units"))
    store.create_run(run_id, mode, manifest, cases)
    return {"run_id": run_id, "mode": mode, "cases": len(cases)}


@app.get("/runs")
async def list_runs():
    return store.list_runs()


@app.post("/runs/{run_id}/observations", dependencies=[Depends(require_runner_token)])
async def runner_observations(run_id: str, body: dict):
    if not store.get_run(run_id):
        raise HTTPException(404, "unknown run")
    obs = body.get("observations") or ([body] if "case_id" in body else [])
    for o in obs:
        store.upsert_runner_observation(run_id, o["case_id"], int(o.get("trial", 1)), o)
        metrics_hooks.ingest_result("runner", "accepted")
        if o.get("latency_ms") is not None:
            metrics.CLIENT_LATENCY.labels(environment=str(o.get("environment")), route=str(o.get("route"))).observe(o["latency_ms"])
    return {"accepted": len(obs)}


def _adjudicate(run_id: str, finalize: bool) -> dict:
    run = store.get_run(run_id)
    if not run:
        raise HTTPException(404, "unknown run")
    cases = store.get_cases(run_id)
    kobs = store.kong_obs_for_run(run_id)
    robs = store.runner_obs_for_run(run_id)
    revision = store.bump_revision(run_id, finalize)
    rows = adj.adjudicate_run(run, cases, kobs, robs, revision)
    for a in rows:
        a["ts"] = int(time.time() * 1000)
    store.insert_adjudications(rows)
    for a in rows:
        _fanout(a)
    summary = adj.summarize(rows, run["manifest"])
    summary["run_id"], summary["revision"], summary["mode"] = run_id, revision, run["mode"]
    summary["unmatched"] = _unmatched_for_run(run_id, cases, kobs, robs)
    return summary


def _unmatched_for_run(run_id, cases, kobs, robs):
    kong_units = {((g.get("runner") or {}).get("case_id"), int((g.get("runner") or {}).get("trial") or 1)) for g in kobs}
    runner_units = set(robs)
    return {
        "kong_without_runner": sorted([list(u) for u in kong_units - runner_units]),
        "runner_without_kong": sorted([list(u) for u in runner_units - kong_units]),
        "labels_without_any_evidence": sorted([c for c in cases if not any(u[0] == c for u in kong_units | runner_units)]),
    }


@app.post("/runs/{run_id}/finalize", dependencies=[Depends(require_runner_token)])
async def finalize(run_id: str):
    return _adjudicate(run_id, finalize=True)


@app.post("/runs/{run_id}/readjudicate", dependencies=[Depends(require_runner_token)])
async def readjudicate(run_id: str):
    return _adjudicate(run_id, finalize=True)


@app.post("/runs/{run_id}/relabel", dependencies=[Depends(require_runner_token)])
async def relabel(run_id: str, body: dict):
    """Human review: correct a label; produces a new adjudication revision (counters recomputed, never inflated)."""
    cases = store.get_cases(run_id)
    cid = body.get("case_id")
    if cid not in cases:
        raise HTTPException(404, "unknown case")
    c = cases[cid]
    for k in ("expected_action", "violation", "category", "label_source", "label_confidence", "disputed", "review_note"):
        if k in body:
            c[k] = body[k]
    c.setdefault("label_history", []).append({"at": time.time(), "by": body.get("reviewer", "unknown"), "change": {k: body[k] for k in body if k != "case_id"}})
    store.update_case(run_id, c)
    return _adjudicate(run_id, finalize=True)


@app.get("/runs/{run_id}/report")
async def report(run_id: str):
    run = store.get_run(run_id)
    if not run:
        raise HTTPException(404, "unknown run")
    adjs = store.latest_adjudications(run_id)
    s = adj.summarize(adjs, run["manifest"])
    s.update({"run_id": run_id, "revision": run["revision"], "mode": run["mode"], "status": run["status"], "manifest": run["manifest"]})
    s["cases"] = [{"case_id": a["case_id"], "trial": a["trial"], "guardrail": a["guardrail"], "stage": a["stage"],
                   "category": a.get("category"), "expected": a["expected"]["action"], "violation": a["expected"]["violation"],
                   "verdict": a["verdict"]["value"], "detector": a["detector"]["outcome"], "enforcement": a["enforcement"]["outcome"],
                   "delivery": a["delivery"]["outcome"], "policy": a["policy"]["outcome"], "gaps": a.get("gaps"),
                   "client_status": (a.get("client") or {}).get("status"), "request_id": a.get("request_id")} for a in adjs]
    return s


@app.get("/runs/{run_id}/cases/{case_id}")
async def case_detail(run_id: str, case_id: str, trial: int = 1):
    adjs = [a for a in store.latest_adjudications(run_id) if a["case_id"] == case_id and a["trial"] == trial]
    kobs = [g for g in store.kong_obs_for_run(run_id) if (g.get("runner") or {}).get("case_id") == case_id and int((g.get("runner") or {}).get("trial") or 1) == trial]
    robs = store.runner_obs_for_run(run_id).get((case_id, trial))
    label = store.get_cases(run_id).get(case_id)
    if not (adjs or kobs or robs):
        raise HTTPException(404, "no evidence for this unit")
    return {"label": label, "adjudications": adjs, "kong_observations": kobs, "runner_observation": robs}


@app.get("/runs/{run_id}/export.{fmt}")
async def export_run(run_id: str, fmt: str):
    adjs = store.latest_adjudications(run_id)
    if fmt == "json":
        return JSONResponse(adjs)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["run_id", "case_id", "trial", "guardrail", "stage", "revision", "category", "expected_action", "violation",
                    "verdict", "detector", "enforcement", "delivery", "policy", "client_status", "gateway_status", "request_id", "gaps"])
        for a in adjs:
            w.writerow([a["run_id"], a["case_id"], a["trial"], a["guardrail"], a["stage"], a["adjudication_revision"], a.get("category"),
                        a["expected"]["action"], a["expected"]["violation"], a["verdict"]["value"], a["detector"]["outcome"],
                        a["enforcement"]["outcome"], a["delivery"]["outcome"], a["policy"]["outcome"],
                        (a.get("client") or {}).get("status"), (a.get("gateway") or {}).get("status"), a.get("request_id"), ";".join(a.get("gaps") or [])])
        return PlainTextResponse(buf.getvalue(), media_type="text/csv")
    raise HTTPException(400, "fmt must be json|csv")


@app.get("/runs/{run_id}/compare/{other_run_id}")
async def compare(run_id: str, other_run_id: str):
    a = adj.summarize(store.latest_adjudications(run_id))
    b = adj.summarize(store.latest_adjudications(other_run_id))
    return {"a": {"run_id": run_id, **a}, "b": {"run_id": other_run_id, **b},
            "delta": {k: (b["detector"]["counts"].get(k, 0) - a["detector"]["counts"].get(k, 0)) for k in a["detector"]["counts"]}}


# ----------------------------------------------------------------- operations
@app.get("/health")
async def health():
    return {"ok": True, "version": VERSION, "destinations": list(DESTINATIONS)}


@app.get("/unmatched")
async def unmatched():
    return store.unmatched(JOIN_TIMEOUT_S)


@app.get("/observations/recent")
async def recent(limit: int = 20):
    rows = store.q("SELECT payload FROM kong_observations ORDER BY received_at DESC LIMIT ?", (min(limit, 200),))
    return [json.loads(r["payload"]) for r in rows]


@app.get("/doctor")
async def doctor(route: str | None = None):
    last = store.q1("SELECT payload, received_at FROM kong_observations ORDER BY received_at DESC LIMIT 1")
    last_gro = json.loads(last["payload"]) if last else None
    route_rows = store.q("SELECT route, COUNT(*) n, MAX(received_at) last FROM kong_observations GROUP BY route")
    runs = store.list_runs(5)
    stages = {
        "plugin_loaded": {"ok": last_gro is not None,
                          "detail": f"observer {last_gro.get('observer_version')} on Kong {last_gro.get('kong_version')}" if last_gro else "no observations received yet"},
        "scope_active": {"ok": any((r["route"] == route) for r in route_rows) if route else bool(route_rows),
                         "detail": {r["route"]: r["n"] for r in route_rows}},
        "evidence_received": {"ok": bool(last_gro and last_gro.get("guardrails")),
                              "detail": (last_gro or {}).get("guardrails"), "gaps": (last_gro or {}).get("gaps")},
        "labels_joined": {"ok": any(r["status"] == "finalized" for r in runs),
                          "detail": [{"run_id": r["run_id"], "status": r["status"], "revision": r["revision"]} for r in runs]},
        "destination_accepted": {d: {"ok": w.last_result[0] if w.last_result else None, "detail": w.last_result[1] if w.last_result else "nothing sent yet",
                                     "last_success_at": w.last_success_at} for d, w in DESTINATIONS.items()} or {"ok": False, "detail": "no destination configured"},
        "dashboard_query_verified": {"ok": None, "detail": "verified by scripts/doctor.sh against Grafana/Splunk APIs, not by the evaluator"},
    }
    return {"stages": stages, "ingest": store.ingest_counts(), "outbox": store.outbox_stats(), "join_timeout_s": JOIN_TIMEOUT_S}


@app.post("/smoke")
async def smoke(wait_s: float = 10.0):
    """Emit a uniquely identifiable synthetic event to every destination and wait for acceptance."""
    smoke_id = f"smoke-{uuid.uuid4().hex[:12]}"
    ev = {"schema_version": adj.SCHEMA_VERSION, "event_type": "smoke_test", "event_id": smoke_id, "smoke_id": smoke_id,
          "ts": int(time.time() * 1000), "environment": os.environ.get("ENVIRONMENT", "local"), "route": "n/a",
          "guardrail": "n/a", "stage": "n/a", "message": "guardrail-evaluator connection test"}
    if not DESTINATIONS:
        return {"smoke_id": smoke_id, "destinations": {}, "note": "no destination configured"}
    _fanout(ev)
    deadline = time.time() + wait_s
    result = {}
    while time.time() < deadline:
        pending = store.q("SELECT destination, status, last_error FROM outbox WHERE event_id=?", (smoke_id,))
        result = {r["destination"]: {"status": r["status"], "error": r["last_error"]} for r in pending}
        if all(v["status"] == "sent" for v in result.values()):
            break
        time.sleep(0.5)
    return {"smoke_id": smoke_id, "destinations": result,
            "search": {"splunk": f'index=* sourcetype="{os.environ.get("SPLUNK_HEC_SOURCETYPE", "kong:guardrail:evaluation")}" smoke_id="{smoke_id}"',
                       "loki": '{service_name="guardrail-evaluator", event_type="smoke_test"} |= "' + smoke_id + '"'}}


# ------------------------------------------------------- ordinary traffic (no labels)
def _passive_summary(window_s: float | None, route: str | None, include_runs: bool) -> dict:
    w = window_s or PASSIVE_WINDOW_S
    since = int((time.time() - w) * 1000)
    s = passive.summarize(store.observations_since(since, include_runs=include_runs, route=route))
    s["window"]["seconds"] = w
    s["window"]["include_runs"] = include_runs
    return s


@app.get("/passive/summary")
async def passive_summary(window_s: float | None = None, route: str | None = None, include_runs: bool = False):
    """Everything the checks on ordinary traffic computed for the window: routes, guardrails, coverage, signals."""
    return _passive_summary(window_s, route, include_runs)


@app.get("/passive/coverage")
async def passive_coverage(window_s: float | None = None, include_runs: bool = False):
    s = _passive_summary(window_s, None, include_runs)
    return {"window": s["window"], "coverage": s["coverage"],
            "routes": {k: {x: v[x] for x in ("requests", "ai_route", "guardrails_enabled", "guardrails_disabled", "probes_expected")} for k, v in s["routes"].items()}}


@app.get("/passive/guardrails/{name}")
async def passive_guardrail(name: str, window_s: float | None = None, include_runs: bool = False):
    s = _passive_summary(window_s, None, include_runs)
    if name not in s["guardrails"]:
        raise HTTPException(404, f"no traffic seen for guardrail {name} in the window")
    return {"window": s["window"], "guardrail": name, **s["guardrails"][name],
            "after_block": s["after_block"].get(name), "signals": [x for x in s["signals"] if x.get("guardrail") == name]}


@app.get("/passive/signals")
async def passive_signals(window_s: float | None = None, include_runs: bool = False):
    s = _passive_summary(window_s, None, include_runs)
    return {"window": s["window"], "signals": s["signals"]}


@app.get("/chain", response_class=HTMLResponse)
async def chain_view():
    """The guardrail chain drawn in 3D with live numbers from /passive/summary (self-contained page, no external assets)."""
    with open(os.path.join(os.path.dirname(__file__), "static", "chain.html"), encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/passive/agreement")
async def passive_agreement(window_s: float = 3600):
    """Cross-check of the probe trail against Kong's own request-debug trace, on requests that carry both.
    The trace is the reference: any 'disagree' is a bug in the probe trail."""
    since = int((time.time() - window_s) * 1000)
    out = {"agree": 0, "consistent_candidates": 0, "disagree": 0, "no_trail": 0, "examples": []}
    for g in store.observations_since(since, include_runs=True):
        ex = g.get("exit") or {}
        if ex.get("attribution") != "request-debug-trace":
            continue
        pt = ex.get("probe_trail")
        if not pt:
            out["no_trail"] += 1
        elif pt.get("plugin_name") == ex.get("plugin_name"):
            out["agree"] += 1
        elif not pt.get("plugin_name") and ex.get("plugin_name") in (pt.get("candidates") or []):
            out["consistent_candidates"] += 1
        else:
            out["disagree"] += 1
            if len(out["examples"]) < 10:
                out["examples"].append({"request_id": g.get("request_id"), "route": (g.get("route") or {}).get("name"),
                                        "trace": ex.get("plugin_name"), "probe_trail": pt})
    out["compared"] = out["agree"] + out["consistent_candidates"] + out["disagree"]
    return out


@app.post("/passive/translate", dependencies=[Depends(require_runner_token)])
async def passive_translate(window_s: float | None = None, include_runs: bool = False, provider: str | None = None):
    """Ask the configured translator (Claude API, Bedrock, or the offline stub) to put the signals in plain language."""
    doc = translate.translate(_passive_summary(window_s, None, include_runs), provider=provider)
    doc["id"] = store.save_findings(doc)
    ev = {"schema_version": adj.SCHEMA_VERSION, "event_type": "findings", "event_id": f"findings-{doc['id']}-{doc['generated_at_ms']}",
          "ts": doc["generated_at_ms"], "environment": os.environ.get("ENVIRONMENT", "local"), "route": "n/a", "guardrail": "n/a", "stage": "n/a",
          "provider": doc["provider"], "headline": doc["headline"], "findings": doc["findings"]}
    _fanout(ev)
    return doc


# separate, demo-only console (404 unless DEMO_CONSOLE=true); see demo.py
demo.translate_now = passive_translate
app.include_router(demo.router)


@app.on_event("startup")
async def _auto_translate():
    """TRANSLATE_EVERY_S > 0: refresh the plain-language findings on a timer (skipped while there is no traffic)."""
    every = float(os.environ.get("TRANSLATE_EVERY_S", "0") or 0)
    if every <= 0:
        return

    async def loop():
        while True:
            await asyncio.sleep(max(every, 30.0))
            try:
                if store.observations_since(time.time() * 1000 - 60_000):
                    await passive_translate()
            except Exception as e:  # never let the timer die
                logging.getLogger("evaluator").warning("auto translate failed: %s", e)

    asyncio.create_task(loop())


@app.get("/passive/findings")
async def passive_findings(limit: int = 1):
    rows = store.latest_findings(min(limit, 50))
    return rows[0] if limit == 1 and rows else rows


@app.post("/outbox/{destination}/requeue")
async def requeue(destination: str):
    return {"requeued": store.requeue_failed(destination)}


@app.get("/metrics")
async def prom():
    return Response(metrics.render(), media_type="text/plain; version=0.0.4")
