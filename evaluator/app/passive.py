"""Checks on ordinary traffic (no labels, no test runner).

Everything here is computed from `kong_observation` events alone, mostly from the probe
trail (docs/probes.md). The output is a set of *signals to investigate*, never a verdict:
without labels nobody can say a block was wrong, only that something looks unusual.

Pure functions over a list of observation dicts so they can be unit-tested without Kong.
"""
from __future__ import annotations

import os
from collections import Counter, defaultdict
from typing import Any, Iterable, Optional

OUR_PLUGINS = ("guardrail-observer", "guardrail-observer-tail")


def _env_f(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


class Thresholds:
    """Tunable through the environment; defaults are deliberately conservative."""

    def __init__(self) -> None:
        self.min_requests = int(_env_f("PASSIVE_MIN_REQUESTS", 20))          # below this a rate is not flagged
        self.high_block_rate = _env_f("PASSIVE_HIGH_BLOCK_RATE", 0.30)
        self.fail_open_ratio = _env_f("PASSIVE_FAIL_OPEN_RATIO", 0.90)       # share of the configured timeout
        self.chain_share = _env_f("PASSIVE_CHAIN_SHARE", 0.30)               # guardrail chain / total duration
        self.retry_window_ms = int(_env_f("PASSIVE_RETRY_WINDOW_S", 120) * 1000)
        self.retry_through_share = _env_f("PASSIVE_RETRY_THROUGH_SHARE", 0.50)
        self.drift_factor = _env_f("PASSIVE_DRIFT_FACTOR", 2.0)
        self.drift_min_requests = int(_env_f("PASSIVE_DRIFT_MIN_REQUESTS", 5))
        self.slow_p95_ms = _env_f("PASSIVE_SLOW_P95_MS", 250)


def quantile(values: list[float], q: float) -> Optional[float]:
    if not values:
        return None
    s = sorted(values)
    if len(s) == 1:
        return float(s[0])
    pos = q * (len(s) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (pos - lo), 2)


def _lat(values: list[float]) -> Optional[dict]:
    if not values:
        return None
    return {"n": len(values), "p50": quantile(values, 0.5), "p95": quantile(values, 0.95), "p99": quantile(values, 0.99),
            "max": round(max(values), 2)}


def _route(g: dict) -> str:
    r = g.get("route") or {}
    return str(r.get("name") or r.get("id") or g.get("route_name") or "unknown") if isinstance(r, dict) else str(r)


def _consumer(g: dict) -> Optional[str]:
    c = g.get("consumer") or {}
    if isinstance(c, dict) and (c.get("username") or c.get("id")):
        return str(c.get("username") or c.get("id"))
    ip = (g.get("native") or {}).get("client_ip")
    return f"ip:{ip}" if ip else None


def _configured_names(g: dict) -> dict[str, bool]:
    """plugin name -> enabled, for every plugin configured on the request's route."""
    out: dict[str, bool] = {}
    for p in ((g.get("configured_plugins") or {}).get("plugins") or []):
        out[p.get("name")] = bool(p.get("enabled")) or out.get(p.get("name"), False)
    return out


def _guardrails_configured(g: dict) -> dict[str, bool]:
    gc = g.get("guardrails_configured")
    if isinstance(gc, list):
        return {x.get("name"): bool(x.get("enabled")) for x in gc if x.get("name")}
    return {}


def _chain_view(r: dict) -> list[dict]:
    """The route's plugins in execution order, each with a display label and a kind.

    kind: probe | guardrail (declared, or one of Kong's own) | router (ai-proxy) | candidate | plugin.
    A candidate is a plugin nobody declared that sits inside the probed stretch of the chain (below the head
    plugin, above the lowest middle probe): it is found by its position, shown under its own name, and gets
    the same per-gap latency and block attribution as a declared guardrail.
    """
    chain = r["_chain"]
    probes = [p for n, p in chain.items() if n.startswith("gro-probe-")]
    head = chain.get("guardrail-observer", 790)
    lo = min(probes) if probes else None
    out = []
    for n, p in sorted(chain.items(), key=lambda kv: -kv[1]):
        if n.startswith("gro-probe-") or n in OUR_PLUGINS:
            kind = "probe"
        elif n in r["guardrails_configured"]:
            kind = "guardrail"
        elif n.startswith("ai-proxy"):
            kind = "router"
        elif lo is not None and lo < p < head:
            kind = "candidate"
        else:
            kind = "plugin"
        out.append({"name": n, "label": r["_labels"].get(n) or n, "priority": p, "kind": kind})
    return out


def apm_view(gro: dict) -> dict:
    """One request as a line: what happened to it and how long each plugin held it (from the probe trail).
    result: served | stopped by <plugin> | waited at <plugin> (allowed after about that guardrail's timeout)."""
    trail = gro.get("trail") or {}
    timeouts = ((gro.get("thresholds") or {}).get("guardrail_timeouts_ms")) or {}
    stopped = ((gro.get("response") or {}).get("source")) == "exit"
    parts, waited = [], None
    for g in trail.get("gaps") or []:
        names = g.get("plugins") if isinstance(g.get("plugins"), list) else []
        if not names:
            continue
        ms = g.get("ms") or 0
        parts.append(f"{' + '.join(names)} {ms:g} ms")
        if not stopped and len(names) == 1 and timeouts.get(names[0]) and ms >= 0.9 * timeouts[names[0]]:
            waited = names[0]
    ex = trail.get("exit") or {}
    cands = ex.get("candidates") if isinstance(ex.get("candidates"), list) else []
    blocker = (gro.get("exit") or {}).get("plugin_name") or ("/".join(cands) if cands else None)
    if stopped and cands:
        parts.append(f"{' / '.join(cands)} {(ex.get('ms') or 0):g} ms x")
    result = f"stopped by {blocker or 'the gateway'}" if stopped else f"waited at {waited}" if waited else "served"
    return {"result": result, "path": "  >  ".join(parts), "stopped_by": blocker if stopped else None}


def _is_ai_route(g: dict) -> bool:
    return any(n and n.startswith("ai-proxy") for n in _configured_names(g)) or bool(g.get("ai_native"))


def _blocked_by(g: dict) -> tuple[Optional[str], Optional[str], list[str]]:
    """(plugin, confidence, candidates) for a request stopped inside the gateway."""
    if (g.get("response") or {}).get("source") != "exit":
        return None, None, []
    ex = g.get("exit") or {}
    cands = (ex.get("probe_trail") or {}).get("candidates") or []
    return ex.get("plugin_name"), ex.get("confidence"), list(cands)


def _verdicts(g: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = defaultdict(list)
    for v in g.get("guardrails") or []:
        if v.get("guardrail"):
            out[v["guardrail"]].append(v)
    return out


def _new_guardrail() -> dict:
    return {"requests": 0, "reached": 0, "blocked": 0, "blocked_by_confidence": Counter(), "blocked_status": Counter(),
            "verdicts": Counter(), "no_verdict": 0, "errors": 0, "detected_not_enforced": 0, "fail_open_suspects": 0,
            "request_rewrites": 0, "response_rewrites": 0, "response_bytes_delta": [], "_lat": [], "shared_gap": 0,
            "blocked_by_consumer": Counter(), "blocked_by_model": Counter(), "candidate_blocks": 0, "timeout_ms": None,
            "routes": Counter(), "disabled_on": set(), "enforced_inline": 0}


def summarize(observations: Iterable[dict], th: Optional[Thresholds] = None, top_n: int = 5) -> dict:
    th = th or Thresholds()
    obs = sorted((o for o in observations if isinstance(o, dict)), key=lambda o: o.get("started_at_ms") or 0)

    guardrails: dict[str, dict] = defaultdict(_new_guardrail)
    routes: dict[str, dict] = {}
    by_consumer: dict[str, list[dict]] = defaultdict(list)
    traffic = {"requests": len(obs), "status": Counter(), "source": Counter(), "tokens": Counter(), "cost": 0.0,
               "models": Counter(), "model_mismatch": 0, "retried": 0, "upstream_errors": 0, "streamed": 0,
               "_ttfc": [], "_stream_chunks": [], "_output_first_chunk_delay": []}

    for g in obs:
        route = _route(g)
        r = routes.setdefault(route, {"requests": 0, "blocked": 0, "ai": False, "guardrails_configured": {}, "probes_expected": [],
                                      "has_trail": False, "_chain_share": [], "_duration": [], "_chain_ms": [], "fingerprints": [],
                                      "environment": g.get("environment"), "shared_gaps": set(), "_events": [], "_chain": {}, "_labels": {}})
        r["requests"] += 1
        r["ai"] = r["ai"] or _is_ai_route(g)
        for p in g.get("plugin_chain") or []:
            if isinstance(p, dict) and p.get("name") and isinstance(p.get("priority"), (int, float)):
                r["_chain"][p["name"]] = p["priority"]
        for x in g.get("guardrails_configured") or []:
            if x.get("name") and isinstance(x.get("priority"), (int, float)):
                r["_chain"][x["name"]] = x["priority"]
        # a human-given name beats the plugin type: Kong lets every plugin instance carry an instance_name
        for p in ((g.get("configured_plugins") or {}).get("plugins") or []):
            if isinstance(p, dict) and p.get("name") and p.get("instance_name"):
                r["_labels"][p["name"]] = p["instance_name"]
        gc = _guardrails_configured(g)
        r["guardrails_configured"].update(gc)
        trail = g.get("trail") or {}
        if trail.get("request"):
            r["has_trail"] = True
            r["probes_expected"] = trail.get("probes_expected") or r["probes_expected"]
        resp = g.get("response") or {}
        status, source = resp.get("status"), resp.get("source")
        traffic["status"][str(status)] += 1
        traffic["source"][str(source)] += 1
        consumer = _consumer(g)
        model = (g.get("request") or {}).get("model") or (g.get("ai") or {}).get("model")
        verdicts = _verdicts(g)
        timeouts = ((g.get("thresholds") or {}).get("guardrail_timeouts_ms")) or {}
        blocker, conf, cands = _blocked_by(g)

        # ---- per-gap evidence -------------------------------------------------
        reached: set[str] = set()
        chain_ms = 0.0
        for gap in trail.get("gaps") or []:
            names = gap.get("plugins") or []
            ms = gap.get("ms") or 0
            chain_ms += ms
            for n in names:
                reached.add(n)
            if len(names) == 1:
                st = guardrails[names[0]]
                st["_lat"].append(ms)
                if gap.get("rewritten"):
                    st["request_rewrites"] += 1
                t = timeouts.get(names[0])
                if t:
                    st["timeout_ms"] = t
                    vs = [v.get("verdict") for v in verdicts.get(names[0], [])]
                    silent_or_allow = (not vs) or all(v in ("allow", "unknown", "skipped", "error") for v in vs)
                    if source != "exit" and ms >= th.fail_open_ratio * t and silent_or_allow:
                        st["fail_open_suspects"] += 1
            elif len(names) > 1:
                r["shared_gaps"].add(tuple(names))
                for n in names:
                    guardrails[n]["shared_gap"] += 1
        ex_trail = trail.get("exit") or {}
        if blocker:
            reached.add(blocker)
            if ex_trail.get("ms") is not None and (ex_trail.get("candidates") or []) == [blocker]:
                guardrails[blocker]["_lat"].append(ex_trail["ms"])
                chain_ms += ex_trail["ms"]
        for gap in trail.get("response_gaps") or []:
            names = gap.get("plugins") or []
            if len(names) == 1 and gap.get("changed"):
                st = guardrails[names[0]]
                st["response_rewrites"] += 1
                st["response_bytes_delta"].append(gap.get("bytes_delta") or 0)
            if gap.get("first_chunk_delay_ms") and names:
                traffic["_output_first_chunk_delay"].append(gap["first_chunk_delay_ms"])

        # ---- per-guardrail counters ----------------------------------------------
        names_here = set(gc) | set(verdicts) | ({blocker} if blocker else set())
        names_here -= set(OUR_PLUGINS)
        for name in names_here:
            st = guardrails[name]
            st["requests"] += 1
            st["routes"][route] += 1
            if gc.get(name) is False:
                st["disabled_on"].add(route)
            vs = verdicts.get(name, [])
            ran = bool(vs and any(v.get("verdict") not in ("not_run",) for v in vs)) or name in reached
            if vs and all(v.get("verdict") == "not_run" for v in vs) and name != blocker:
                ran = False
            if ran:
                st["reached"] += 1
                for v in vs:
                    st["verdicts"][str(v.get("verdict"))] += 1
                if not vs or all(v.get("verdict") in ("unknown", None) for v in vs):
                    if name != blocker:
                        st["no_verdict"] += 1
                if any(v.get("verdict") == "error" for v in vs):
                    st["errors"] += 1
                if source != "exit" and any(v.get("verdict") in ("deny", "detect") and v.get("enforced_by") for v in vs):
                    st["enforced_inline"] += 1      # acted without ending the request: redaction, replacement, stream abort
                if any(v.get("verdict") in ("deny", "detect") for v in vs) and source != "exit" and not any(
                        v.get("enforced_by") for v in vs if v.get("verdict") in ("deny", "detect")):
                    st["detected_not_enforced"] += 1
        if blocker:
            st = guardrails[blocker]
            st["blocked"] += 1
            st["blocked_by_confidence"][str(conf)] += 1
            st["blocked_status"][str(status)] += 1
            if consumer:
                st["blocked_by_consumer"][consumer] += 1
            if model:
                st["blocked_by_model"][str(model)] += 1
            r["blocked"] += 1
        elif source == "exit":
            r["blocked"] += 1
            for c in cands:
                guardrails[c]["candidate_blocks"] += 1

        # ---- route cost -----------------------------------------------------------
        dur = g.get("duration_ms")
        if dur and trail.get("gaps") is not None and source != "exit":
            r["_chain_ms"].append(chain_ms)
            r["_duration"].append(dur)
            r["_chain_share"].append(min(1.0, chain_ms / dur) if dur > 0 else 0.0)
        fp = g.get("policy_fingerprint")
        r["_events"].append({"t": g.get("started_at_ms") or 0, "fp": fp, "blocked": source == "exit", "chain_ms": chain_ms})

        # ---- traffic facts -----------------------------------------------------------
        for plugin, v in (g.get("ai_native") or {}).items():
            usage, meta = v.get("usage") or {}, v.get("meta") or {}
            for k in ("prompt_tokens", "completion_tokens", "total_tokens"):
                if isinstance(usage.get(k), (int, float)):
                    traffic["tokens"][k] += usage[k]
            if isinstance(usage.get("cost"), (int, float)):
                traffic["cost"] += usage["cost"]
            if meta.get("response_model") or meta.get("request_model"):
                traffic["models"][str(meta.get("response_model") or meta.get("request_model"))] += 1
                if meta.get("request_model") and meta.get("response_model") and meta["request_model"] != meta["response_model"]:
                    traffic["model_mismatch"] += 1
        if len(g.get("attempts") or []) > 1:
            traffic["retried"] += 1
        if source == "error" or (source == "service" and isinstance(status, int) and status >= 500):
            traffic["upstream_errors"] += 1
        if (g.get("request") or {}).get("stream_requested"):
            traffic["streamed"] += 1
            s = g.get("stream") or {}
            if s.get("first_chunk_at_ms") and g.get("started_at_ms"):
                traffic["_ttfc"].append(s["first_chunk_at_ms"] - g["started_at_ms"])
            if s.get("chunks"):
                traffic["_stream_chunks"].append(s["chunks"])

        if consumer:
            by_consumer[consumer].append({"t": g.get("started_at_ms") or 0, "blocked": source == "exit", "blocker": blocker,
                                          "route": route, "body": (g.get("request") or {}).get("body_sha256")})

    # ---- behaviour after a block ------------------------------------------------------
    after: dict[str, dict] = defaultdict(lambda: {"blocks": 0, "followed_by_retry": 0, "retry_blocked_again": 0,
                                                  "retry_got_through": 0, "retry_changed_body": 0})
    repeat_offenders: Counter = Counter()
    for consumer, evs in by_consumer.items():
        for i, e in enumerate(evs):
            if not e["blocked"]:
                continue
            key = e["blocker"] or "unattributed"
            a = after[key]
            a["blocks"] += 1
            repeat_offenders[consumer] += 1
            nxt = next((n for n in evs[i + 1:] if n["route"] == e["route"] and n["t"] - e["t"] <= th.retry_window_ms), None)
            if nxt:
                a["followed_by_retry"] += 1
                a["retry_blocked_again" if nxt["blocked"] else "retry_got_through"] += 1
                if e["body"] and nxt["body"] and e["body"] != nxt["body"]:
                    a["retry_changed_body"] += 1

    # ---- drift across a guardrail config change ---------------------------------------
    drift = []
    for route, r in routes.items():
        evs = [e for e in r["_events"] if e["fp"]]
        fps = []
        for e in evs:
            if not fps or fps[-1] != e["fp"]:
                fps.append(e["fp"])
        r["fingerprints"] = fps
        if len(fps) < 2:
            continue
        cut = next(i for i, e in enumerate(evs) if e["fp"] != evs[0]["fp"])
        before, afterw = evs[:cut], evs[cut:]
        def rate(xs): return round(sum(1 for x in xs if x["blocked"]) / len(xs), 4) if xs else None
        drift.append({"route": route, "changed_at_ms": afterw[0]["t"], "from": evs[0]["fp"], "to": afterw[0]["fp"],
                      "changes_in_window": len(fps) - 1, "n_before": len(before), "n_after": len(afterw),
                      "block_rate_before": rate(before), "block_rate_after": rate(afterw),
                      "chain_p95_ms_before": quantile([x["chain_ms"] for x in before], 0.95),
                      "chain_p95_ms_after": quantile([x["chain_ms"] for x in afterw], 0.95)})

    # ---- shape the output --------------------------------------------------------------
    g_out = {}
    for name, st in guardrails.items():
        if st["requests"] == 0 and st["blocked"] == 0 and not st["_lat"]:
            continue
        reached = st["reached"] or 0
        g_out[name] = {
            "requests": st["requests"], "reached": reached, "blocked": st["blocked"],
            "block_rate": round(st["blocked"] / reached, 4) if reached else None,
            "enforced_inline": st["enforced_inline"],
            "intervention_rate": round((st["blocked"] + st["enforced_inline"]) / reached, 4) if reached else None,
            "blocked_by_confidence": dict(st["blocked_by_confidence"]), "blocked_status": dict(st["blocked_status"]),
            "candidate_blocks": st["candidate_blocks"],
            "verdicts": dict(st["verdicts"]), "no_verdict": st["no_verdict"], "errors": st["errors"],
            "detected_not_enforced": st["detected_not_enforced"],
            "latency_ms": _lat(st["_lat"]), "latency_shared_gap_requests": st["shared_gap"],
            "timeout_ms": st["timeout_ms"], "fail_open_suspects": st["fail_open_suspects"],
            "request_rewrites": st["request_rewrites"], "response_rewrites": st["response_rewrites"],
            "response_bytes_delta_mean": round(sum(st["response_bytes_delta"]) / len(st["response_bytes_delta"]), 1) if st["response_bytes_delta"] else None,
            "top_blocked_consumers": st["blocked_by_consumer"].most_common(top_n),
            "blocked_by_model": dict(st["blocked_by_model"]),
            "routes": dict(st["routes"]), "disabled_on": sorted(st["disabled_on"]),
        }

    r_out, coverage = {}, []
    ai_routes = {n for n, r in routes.items() if r["ai"]}
    all_guardrails_on_ai = Counter()
    for n in ai_routes:
        for gname, enabled in routes[n]["guardrails_configured"].items():
            if enabled:
                all_guardrails_on_ai[gname] += 1
    for name, r in routes.items():
        enabled = sorted(k for k, v in r["guardrails_configured"].items() if v)
        disabled = sorted(k for k, v in r["guardrails_configured"].items() if not v)
        r_out[name] = {
            "requests": r["requests"], "blocked": r["blocked"],
            "block_rate": round(r["blocked"] / r["requests"], 4) if r["requests"] else None,
            "ai_route": r["ai"], "guardrails_enabled": enabled, "guardrails_disabled": disabled,
            "probes_expected": r["probes_expected"], "has_trail": r["has_trail"],
            "chain_ms": _lat(r["_chain_ms"]), "duration_ms": _lat(r["_duration"]),
            "chain_share_p50": quantile(r["_chain_share"], 0.5),
            "shared_gaps": [list(x) for x in sorted(r["shared_gaps"])], "policy_fingerprints": r["fingerprints"],
            "chain": _chain_view(r),
            "environment": r["environment"],
        }
        if not r["ai"]:
            continue
        if not enabled:
            coverage.append({"route": name, "kind": "ai_route_without_guardrail", "requests": r["requests"],
                             "detail": "requests reach a model on this route and no known guardrail plugin is enabled on it"})
        for gname in disabled:
            coverage.append({"route": name, "kind": "guardrail_disabled", "guardrail": gname, "requests": r["requests"],
                             "detail": "configured on the route but switched off"})
        for gname, n_routes in all_guardrails_on_ai.items():
            if gname not in enabled and n_routes >= 1 and len(ai_routes) > 1 and gname not in disabled:
                coverage.append({"route": name, "kind": "guardrail_missing_vs_peers", "guardrail": gname, "requests": r["requests"],
                                 "detail": f"enabled on {n_routes} other AI route(s), absent here"})
        if enabled and not r["probes_expected"]:
            coverage.append({"route": name, "kind": "no_probes", "requests": r["requests"],
                             "detail": "guardrails present but no gro-probe-* on the route: no per-guardrail latency, blocks are attributed with lower confidence"})
        for names in sorted(r["shared_gaps"]):
            if sum(1 for x in names if x in r["guardrails_configured"]) > 1:
                coverage.append({"route": name, "kind": "guardrails_share_a_gap", "guardrails": list(names), "requests": r["requests"],
                                 "detail": "no probe between these plugins: leave a free priority between guardrails and regenerate the probes"})

    t_out = {
        "requests": traffic["requests"], "status": dict(traffic["status"]), "source": dict(traffic["source"]),
        "tokens": dict(traffic["tokens"]), "cost": round(traffic["cost"], 6), "models": dict(traffic["models"]),
        "model_mismatch": traffic["model_mismatch"], "retried": traffic["retried"], "upstream_errors": traffic["upstream_errors"],
        "streamed": traffic["streamed"], "time_to_first_chunk_ms": _lat(traffic["_ttfc"]),
        "stream_chunks": _lat(traffic["_stream_chunks"]),
        "output_guard_first_chunk_delay_ms": _lat(traffic["_output_first_chunk_delay"]),
    }
    out = {
        "window": {"from_ms": obs[0].get("started_at_ms") if obs else None, "to_ms": obs[-1].get("started_at_ms") if obs else None,
                   "requests": len(obs)},
        "routes": r_out, "guardrails": g_out, "coverage": coverage,
        "after_block": {k: v for k, v in after.items()}, "repeat_blocked_consumers": repeat_offenders.most_common(top_n),
        "drift": drift, "traffic": t_out,
    }
    out["signals"] = signals(out, th)
    return out


def signals(s: dict, th: Optional[Thresholds] = None) -> list[dict]:
    """Things worth a human look, each with the numbers behind it. Wording stays neutral on purpose."""
    th = th or Thresholds()
    sig: list[dict] = []

    def add(kind, severity, summary, **scope_and_evidence):
        sig.append({"kind": kind, "severity": severity, "status": "investigate", "summary": summary, **scope_and_evidence})

    for c in s["coverage"]:
        sev = "warn" if c["kind"] in ("ai_route_without_guardrail", "guardrail_disabled", "guardrail_missing_vs_peers") else "info"
        what = c.get("guardrail") or ", ".join(c.get("guardrails") or []) or "guardrails"
        add("coverage:" + c["kind"], sev, f"{c['route']}: {what} - {c['detail']}", route=c["route"], guardrail=c.get("guardrail"),
            evidence={"requests": c["requests"]})
    for name, g in s["guardrails"].items():
        if g["intervention_rate"] is not None and g["reached"] >= th.min_requests and g["intervention_rate"] >= th.high_block_rate:
            n = g["blocked"] + g["enforced_inline"]
            add("high_block_rate", "warn", f"{name} stopped or altered {n} of {g['reached']} requests ({g['intervention_rate']:.0%}). "
                "Could be an attack wave or overcatching: sample the affected requests.", guardrail=name,
                evidence={"blocked": g["blocked"], "enforced_inline": g["enforced_inline"], "reached": g["reached"],
                          "top_consumers": g["top_blocked_consumers"]})
        if g["fail_open_suspects"]:
            add("suspected_fail_open", "warn", f"{name} let {g['fail_open_suspects']} request(s) through after about its {g['timeout_ms']} ms "
                "timeout with no decision recorded. Check its backend and its behaviour on timeout.", guardrail=name,
                evidence={"count": g["fail_open_suspects"], "timeout_ms": g["timeout_ms"], "latency_ms": g["latency_ms"]})
        if g["no_verdict"]:
            add("no_verdict", "info", f"{name} ran on {g['no_verdict']} request(s) without recording a decision. It may be fine, "
                "but its allow/deny behaviour cannot be observed.", guardrail=name, evidence={"count": g["no_verdict"], "reached": g["reached"]})
        if g["errors"]:
            add("guardrail_errors", "warn", f"{name} reported an error on {g['errors']} request(s).", guardrail=name, evidence={"count": g["errors"]})
        if g["detected_not_enforced"]:
            add("detected_not_enforced", "warn", f"{name} flagged {g['detected_not_enforced']} request(s) that were still served. "
                "Expected in detect-only mode; a slip if it is meant to block.", guardrail=name, evidence={"count": g["detected_not_enforced"]})
        lat = g["latency_ms"]
        if lat and lat["n"] >= th.min_requests and lat["p95"] is not None and lat["p95"] >= th.slow_p95_ms:
            add("slow_guardrail", "info", f"{name} p95 latency is {lat['p95']} ms over {lat['n']} requests.", guardrail=name, evidence=lat)
        if g["disabled_on"]:
            pass  # reported under coverage
    for route, r in s["routes"].items():
        if r["chain_share_p50"] is not None and r["requests"] >= th.min_requests and r["chain_share_p50"] >= th.chain_share:
            add("chain_cost", "info", f"{route}: the guardrail chain takes {r['chain_share_p50']:.0%} of gateway time at the median.",
                route=route, evidence={"chain_ms": r["chain_ms"], "duration_ms": r["duration_ms"]})
    for name, a in s["after_block"].items():
        if a["followed_by_retry"] >= 3 and a["retry_got_through"] / a["followed_by_retry"] >= th.retry_through_share:
            add("retry_gets_through", "warn", f"After a block by {name}, {a['retry_got_through']} of {a['followed_by_retry']} retries by the same "
                f"caller got through ({a['retry_changed_body']} with a changed body). Either callers rephrase honest requests "
                "(overcatch) or the block is easy to step around (slip).", guardrail=name, evidence=a)
        elif a["followed_by_retry"] >= 5 and a["retry_blocked_again"] == a["followed_by_retry"]:
            add("retry_storm", "info", f"After a block by {name}, callers retried {a['followed_by_retry']} times and were blocked every time.",
                guardrail=name, evidence=a)
    for d in s["drift"]:
        b, a = d["block_rate_before"], d["block_rate_after"]
        enough = d["n_before"] >= th.drift_min_requests and d["n_after"] >= th.drift_min_requests
        moved = (b is not None and a is not None and enough and
                 ((b == 0 and a > 0.05) or (a == 0 and b > 0.05) or (b > 0 and (a / b >= th.drift_factor or a / b <= 1 / th.drift_factor))))
        add("guardrail_config_changed", "warn" if moved else "info",
            f"{d['route']}: guardrail configuration changed; block rate {b} -> {a} "
            f"({d['n_before']} requests before, {d['n_after']} after)" + ("" if enough else ", too few requests to compare"),
            route=d["route"], evidence=d)
    t = s["traffic"]
    if t["model_mismatch"]:
        add("model_differs_from_request", "info", f"{t['model_mismatch']} request(s) were answered by a different model than requested.",
            evidence={"count": t["model_mismatch"]})
    if t["requests"] >= th.min_requests and t["upstream_errors"] / t["requests"] >= 0.05:
        add("upstream_errors", "warn", f"{t['upstream_errors']} of {t['requests']} requests failed upstream.",
            evidence={"count": t["upstream_errors"], "requests": t["requests"]})
    return sig
