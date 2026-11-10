#!/usr/bin/env python3
"""Active test runner: sends labeled cases through a Kong route and records what the client actually received.

Ground truth (labels) is sent ONLY to the evaluator, never to Kong. Kong receives
signed, opaque runner metadata (run_id;case_id;trial;sent_at_ms + HMAC) so the
observer can correlate without trusting the client.

usage: runner.py --suite cases/prompt-guard.yaml [--trials 1] [--mode evaluate|observe]
env:   KONG_URL, EVALUATOR_URL, RUNNER_TOKEN, RUNNER_SECRET, RUNNER_APIKEY
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import time
import uuid

import httpx
import yaml

KONG_URL = os.environ.get("KONG_URL", "http://localhost:8000")
EVALUATOR_URL = os.environ.get("EVALUATOR_URL", "http://localhost:8800")
RUNNER_TOKEN = os.environ.get("RUNNER_TOKEN", "")
RUNNER_SECRET = os.environ.get("RUNNER_SECRET", "")
RUNNER_APIKEY = os.environ.get("RUNNER_APIKEY", "")
KONG_REQUEST_DEBUG_TOKEN = os.environ.get("KONG_REQUEST_DEBUG_TOKEN", "")
REFUSAL_RE = re.compile(r"\b(i can(?:'|no)t|i cannot|i'm unable|i am unable|not able to help|against (?:my|the) (?:policy|guidelines))\b", re.I)


def now_ms() -> int:
    return int(time.time() * 1000)


def sign(secret: str, value: str) -> str:
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def load_suite(path: str) -> dict:
    with open(path) as f:
        suite = yaml.safe_load(f)
    for c in suite["cases"]:
        c.setdefault("stage", suite.get("stage", "input"))
        c.setdefault("guardrail", suite.get("guardrail"))
        c.setdefault("synthetic", suite.get("synthetic", False))
        c.setdefault("label_source", suite.get("label_source", "human"))
        c.setdefault("violation_marker", suite.get("violation_marker", "[[VIOLATION]]"))
    return suite


def ev_client(token: str) -> httpx.Client:
    return httpx.Client(base_url=EVALUATOR_URL, headers={"Authorization": f"Bearer {token}"} if token else {}, timeout=30)


def sse_content(raw: str) -> str:
    """Concatenate delta.content from an SSE body (OpenAI chunk format)."""
    out = []
    for line in raw.splitlines():
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if not data or data == "[DONE]":
            continue
        try:
            j = json.loads(data)
        except Exception:  # noqa: BLE001
            continue
        for ch in j.get("choices") or []:
            d = ch.get("delta") or {}
            if isinstance(d.get("content"), str):
                out.append(d["content"])
            elif isinstance(d.get("reasoning_content"), str):
                out.append(d["reasoning_content"])
    return "".join(out)


def json_content(raw: str) -> str | None:
    try:
        j = json.loads(raw)
    except Exception:  # noqa: BLE001
        return None
    for ch in j.get("choices") or []:
        m = ch.get("message") or {}
        if isinstance(m.get("content"), str) and m["content"]:
            return m["content"]
        if isinstance(m.get("reasoning_content"), str) and m["reasoning_content"]:
            return m["reasoning_content"]  # reasoning models may spend the whole budget thinking
    return None


def send_case(http: httpx.Client, suite: dict, case: dict, run_id: str, trial: int, timeout_s: float, passive: bool = False) -> dict:
    body = {"model": case.get("model", suite.get("model", "mock-gpt")), "messages": case["messages"], "stream": bool(case.get("stream"))}
    if case.get("max_tokens"):
        body["max_tokens"] = case["max_tokens"]
    sent_at = now_ms()
    meta = f"{run_id};{case['case_id']};{trial};{sent_at}"
    headers = {"Content-Type": "application/json", "X-Observer-Run": meta, "X-Observer-Sig": sign(RUNNER_SECRET, meta) if RUNNER_SECRET else "",
               # identity by default so received bytes are inspectable; case.gzip=true exercises the compressed path
               "Accept-Encoding": "gzip" if case.get("gzip") else "identity"}
    if case.get("unsigned"):
        headers.pop("X-Observer-Sig")
    if passive:
        # ordinary traffic: no runner identity, no request-debug trace. Kong sees what any client would send.
        headers.pop("X-Observer-Run", None)
        headers.pop("X-Observer-Sig", None)
    if KONG_REQUEST_DEBUG_TOKEN and not case.get("no_request_debug") and not passive:
        # Kong strips these before any plugin runs; the observer reads the resulting trace in its log phase
        headers["X-Kong-Request-Debug"] = "*"
        headers["X-Kong-Request-Debug-Token"] = KONG_REQUEST_DEBUG_TOKEN
    apikey = case.get("apikey_override", RUNNER_APIKEY)
    if apikey:
        headers["apikey"] = apikey
    url = KONG_URL.rstrip("/") + suite["path"]
    marker = case.get("violation_marker")
    obs = {"case_id": case["case_id"], "trial": trial, "sent_at_ms": sent_at, "route": suite["route"], "environment": suite.get("environment", "local"),
           "stream": bool(case.get("stream")), "chunks": [], "marker_seen": None, "marker_first_at_ms": None, "marker_chunk_index": None,
           "model_answered": False, "refusal_like": None, "error": None, "status": None, "body_bytes": 0, "body_sha256": None}
    t0 = time.perf_counter()
    raw_parts: list[bytes] = []
    try:
        with http.stream("POST", url, json=body, headers=headers, timeout=timeout_s) as r:
            obs["status"] = r.status_code
            obs["request_id"] = r.headers.get("x-kong-request-id")
            obs["content_type"] = r.headers.get("content-type")
            obs["response_headers"] = {k: v for k, v in r.headers.items() if k.lower().startswith(("x-kong", "x-guardrail", "x-fixture", "content-type")) and k.lower() != "x-kong-request-debug-output"}
            dbg = r.headers.get("x-kong-request-debug-output")
            if dbg:
                try:
                    obs["request_debug_output"] = json.loads(dbg)  # client-side copy of Kong's phase trace
                except Exception:  # noqa: BLE001
                    obs["request_debug_output"] = {"raw": dbg[:2000]}
            idx = 0
            acc = b""
            obs["content_encoding"] = r.headers.get("content-encoding")
            # iter_bytes() transparently decodes Content-Encoding (gzip) so marker checks see plaintext
            for chunk in (r.iter_bytes() if obs["content_encoding"] else r.iter_raw()):
                t = time.perf_counter()
                if idx == 0:
                    obs["ttfb_ms"] = round((t - t0) * 1000, 1)
                idx += 1
                raw_parts.append(chunk)
                acc += chunk
                if len(obs["chunks"]) < 512:
                    obs["chunks"].append({"t": round((t - t0) * 1000, 1), "n": len(chunk)})
                if marker and obs["marker_seen"] is None and marker.encode() in acc:
                    obs["marker_seen"] = True
                    obs["marker_first_at_ms"] = sent_at + int((t - t0) * 1000)
                    obs["marker_chunk_index"] = idx
            obs["chunk_count"] = idx
    except httpx.TimeoutException:
        obs["error"] = "timeout"
    except httpx.TransportError as e:
        obs["error"] = "connection_error"
        obs["error_detail"] = str(e)[:200]
    obs["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    raw = b"".join(raw_parts)
    obs["body_bytes"] = len(raw)
    obs["body_sha256"] = hashlib.sha256(raw).hexdigest() if raw else None
    text = raw.decode("utf-8", errors="replace")
    if marker and obs["marker_seen"] is None:
        obs["marker_seen"] = False
    content = sse_content(text) if "text/event-stream" in (obs.get("content_type") or "") else json_content(text)
    obs["model_answered"] = bool(content) and (obs["status"] or 0) < 400
    obs["content_chars"] = len(content or "")
    obs["refusal_like"] = bool(REFUSAL_RE.search(content)) if content else None
    obs["body_excerpt"] = text[:300]
    if case.get("expected_action") in ("redact", "transform"):
        absent = [s for s in case.get("expected_absent", []) if s in (content or text)]
        present = [s for s in case.get("expected_present", []) if s not in (content or text)]
        obs["transform_check"] = {"ok": not absent and not present, "reason": f"leaked={absent} missing={present}"}
    return obs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", action="append", required=True)
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--mode", default="evaluate", choices=["evaluate", "observe"])
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--settle", type=float, default=4.0, help="seconds to wait for http-log batches before finalizing")
    ap.add_argument("--only", help="comma-separated case ids")
    ap.add_argument("--fail-on", default="unmatched", help="comma list of: unmatched,fp,fn,enforcement")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--passive", action="store_true",
                    help="send the cases as ordinary traffic (unsigned, no request-debug header, no labels sent anywhere); "
                         "each case is sent `repeat` times; then print the evaluator's signals")
    args = ap.parse_args()

    rc = 0
    for path in args.suite:
        suite = load_suite(path)
        cases = suite["cases"]
        if args.only:
            keep = set(args.only.split(","))
            cases = [c for c in cases if c["case_id"] in keep]
        if args.passive:
            sent = 0
            with httpx.Client() as http:
                for c in cases:
                    for i in range(int(c.get("repeat", 1))):
                        o = send_case(http, suite, c, "passive", i + 1, c.get("timeout_s", args.timeout), passive=True)
                        sent += 1
                        if i == 0:
                            print(f"  {c['case_id']:<32} x{c.get('repeat', 1):<3} status={o['status']} err={o['error']} {o['latency_ms']}ms", file=sys.stderr)
                        if c.get("pause_s"):
                            time.sleep(float(c["pause_s"]))
            time.sleep(args.settle)
            with ev_client(RUNNER_TOKEN) as ev:
                s = ev.get("/passive/summary", params={"window_s": 3600}).json()
            if args.json:
                print(json.dumps(s, indent=2))
            else:
                print(f"\n== {suite['suite']} as ordinary traffic: {sent} request(s) sent; window holds {s['window']['requests']} ==")
                for name, g in s["guardrails"].items():
                    lat = g["latency_ms"] or {}
                    print(f"  {name:<24} reached={g['reached']:<4} blocked={g['blocked']:<3} altered={g['enforced_inline']:<3} rate={g['intervention_rate']} p95={lat.get('p95')}ms "
                          f"fail_open_suspects={g['fail_open_suspects']} no_verdict={g['no_verdict']} rewrites={g['request_rewrites']}/{g['response_rewrites']}")
                for x in s["signals"]:
                    print(f"  [{x['severity']}] {x['kind']}: {x['summary']}")
            continue
        run_id = f"{suite['suite']}-{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:4]}"
        labels = [{k: v for k, v in c.items() if k not in ("messages", "model", "unsigned", "apikey_override")} for c in cases]
        manifest = {"suite": suite["suite"], "route": suite["route"], "guardrail": suite.get("guardrail"), "policy_version": suite.get("policy_version"),
                    "environment": suite.get("environment", "local"), "trials": args.trials, "expected_units": len(cases) * args.trials,
                    "kong_url": KONG_URL, "runner_version": "0.1.0", "label_source": suite.get("label_source", "human"), "synthetic": suite.get("synthetic", False)}
        with ev_client(RUNNER_TOKEN) as ev:
            r = ev.post("/runs", json={"run_id": run_id, "mode": args.mode, "cases": labels, "manifest": manifest})
            r.raise_for_status()
            print(f"[{suite['suite']}] run {run_id}: {len(cases)} cases x {args.trials} trial(s) via {KONG_URL}{suite['path']}", file=sys.stderr)
            obs_batch = []
            with httpx.Client() as http:
                for trial in range(1, args.trials + 1):
                    for c in cases:
                        o = send_case(http, suite, c, run_id, trial, c.get("timeout_s", args.timeout))
                        obs_batch.append(o)
                        print(f"  {c['case_id']:<32} trial={trial} status={o['status']} err={o['error']} marker={o['marker_seen']} "
                              f"answered={o['model_answered']} {o['latency_ms']}ms", file=sys.stderr)
            ev.post(f"/runs/{run_id}/observations", json={"observations": obs_batch}).raise_for_status()
            time.sleep(args.settle)
            rep = ev.post(f"/runs/{run_id}/finalize").json()
        if args.json:
            print(json.dumps(rep, indent=2))
        else:
            d = rep["detector"]
            print(f"\n== {run_id} (revision {rep['revision']}, mode {rep['mode']}) ==")
            print(f"units={rep['units']} expected={rep['expected_units']} reconciled={rep['reconciled']}")
            print(f"TP={d['counts']['TP']} FP={d['counts']['FP']} FN={d['counts']['FN']} TN={d['counts']['TN']} "
                  f"INCONCLUSIVE={d['counts']['INCONCLUSIVE']} EXCLUDED={d['counts']['EXCLUDED']} ERROR={d['counts']['ERROR']}")
            print(f"FPR={d['fpr_display']} ({d['fpr']})  FNR={d['fnr_display']} ({d['fnr']})  labeled_coverage={d['labeled_coverage']}")
            print(f"enforcement_failures={rep['enforcement_failures']} benign_blocked_or_altered={rep['benign_blocked_or_altered']} "
                  f"violations_delivered={rep['violations_delivered']}")
            print(f"policy={rep['policy']}")
            um = rep.get("unmatched", {})
            if any(um.values()):
                print(f"unmatched={json.dumps(um)}")
            print(f"report: {EVALUATOR_URL}/runs/{run_id}/report   csv: {EVALUATOR_URL}/runs/{run_id}/export.csv")
        fail_on = set(args.fail_on.split(","))
        um = rep.get("unmatched", {})
        if "unmatched" in fail_on and any(um.values()):
            rc = 2
        if "fp" in fail_on and rep["detector"]["counts"]["FP"]:
            rc = 3
        if "fn" in fail_on and rep["detector"]["counts"]["FN"]:
            rc = 3
        if "enforcement" in fail_on and rep["enforcement_failures"]:
            rc = 3
    return rc


if __name__ == "__main__":
    sys.exit(main())
