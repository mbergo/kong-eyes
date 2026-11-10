#!/usr/bin/env python3
"""Generates dashboards/guardrail-live.json: the guardrail chain on ordinary traffic, one screen.
Series are the evaluator's go_live_* gauges (recomputed over PASSIVE_WINDOW_S) plus Kong's own request counters."""
import json
import pathlib

PROM = {"type": "prometheus", "uid": "go-prom"}
LOKI = {"type": "loki", "uid": "go-loki"}
G = 'guardrail=~"$guardrail", guardrail!="header-guardrail"'
R = 'route=~"$route"'
_id = [0]


def nid():
    _id[0] += 1
    return _id[0]


def pos(x, y, w, h):
    return {"x": x, "y": y, "w": w, "h": h}


def stat(title, expr, x, y, w=4, h=4, unit="none", steps=None, desc="", decimals=None):
    d = {"unit": unit, "noValue": "0", "thresholds": {"mode": "absolute", "steps": steps or [{"color": "text", "value": None}]},
         "color": {"mode": "thresholds"}}
    if decimals is not None:
        d["decimals"] = decimals
    return {"id": nid(), "type": "stat", "title": title, "description": desc, "datasource": PROM, "gridPos": pos(x, y, w, h),
            "targets": [{"expr": expr, "refId": "A", "instant": True}], "fieldConfig": {"defaults": d, "overrides": []},
            "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "value", "graphMode": "none", "textMode": "value"}}


def ts(title, targets, x, y, w=12, h=8, unit="short", desc="", stack=False, maxv=None, bars=False):
    custom = {"lineWidth": 2, "fillOpacity": 25 if stack else 8, "showPoints": "never", "spanNulls": True,
              "stacking": {"mode": "normal" if stack else "none"}, "drawStyle": "bars" if bars else "line"}
    d = {"unit": unit, "custom": custom, "min": 0}
    if maxv is not None:
        d["max"] = maxv
    return {"id": nid(), "type": "timeseries", "title": title, "description": desc, "datasource": PROM, "gridPos": pos(x, y, w, h),
            "targets": [dict(t, refId=chr(65 + i)) for i, t in enumerate(targets)], "fieldConfig": {"defaults": d, "overrides": []},
            "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi", "sort": "desc"}}}


def bars(title, expr, legend, x, y, w=8, h=7, unit="short", desc="", steps=None, maxv=None):
    d = {"unit": unit, "min": 0, "color": {"mode": "thresholds"},
         "thresholds": {"mode": "absolute", "steps": steps or [{"color": "blue", "value": None}]}}
    if maxv is not None:
        d["max"] = maxv
    return {"id": nid(), "type": "bargauge", "title": title, "description": desc, "datasource": PROM, "gridPos": pos(x, y, w, h),
            "targets": [{"expr": expr, "refId": "A", "instant": True, "legendFormat": legend}],
            "fieldConfig": {"defaults": d, "overrides": []},
            "options": {"orientation": "horizontal", "displayMode": "basic", "reduceOptions": {"calcs": ["lastNotNull"]},
                        "showUnfilled": True, "valueMode": "color", "namePlacement": "left"}}


def text(md, x, y, w=24, h=2):
    return {"id": nid(), "type": "text", "title": "", "gridPos": pos(x, y, w, h), "options": {"mode": "markdown", "content": md}, "transparent": True}


def row(title, y):
    return {"id": nid(), "type": "row", "title": title, "collapsed": False, "gridPos": pos(0, y, 24, 1), "panels": []}


def logs(title, expr, x, y, w=24, h=8):
    return {"id": nid(), "type": "logs", "title": title, "datasource": LOKI, "gridPos": pos(x, y, w, h),
            "targets": [{"expr": expr, "refId": "A"}],
            "options": {"showTime": True, "wrapLogMessage": True, "prettifyLogMessage": True, "enableLogDetails": True, "sortOrder": "Descending"}}


def var(name, label, query):
    return {"name": name, "label": label, "type": "query", "datasource": PROM, "query": {"query": query, "refId": "v"}, "definition": query,
            "includeAll": True, "multi": True, "refresh": 2, "sort": 1, "allValue": ".*",
            "current": {"selected": True, "text": ["All"], "value": ["$__all"]}}


warn = [{"color": "green", "value": None}, {"color": "orange", "value": 1}]
bad = [{"color": "green", "value": None}, {"color": "red", "value": 1}]
rate_steps = [{"color": "green", "value": None}, {"color": "orange", "value": 0.2}, {"color": "red", "value": 0.4}]
lat_steps = [{"color": "green", "value": None}, {"color": "orange", "value": 100}, {"color": "red", "value": 300}]

p, y = [], 0
p.append(text("**Signals, not verdicts.** Ordinary traffic carries no labels, so nothing here proves a guardrail right or wrong: each number is a place to look. "
              "Values are recomputed over the evaluator's sliding window (`PASSIVE_WINDOW_S`). Evidence behind every number: evaluator `/passive/summary`. "
              "The same chain drawn in 3D: evaluator `/chain`.", 0, y)); y += 2
p += [
    stat("Requests in window", f'sum(go_live_requests{{{R}}})', 0, y, 3),
    stat("Stopped in the gateway", f'sum(go_live_route_blocked{{{R}}}) / sum(go_live_requests{{{R}}})', 3, y, 3, unit="percentunit", decimals=1,
         steps=rate_steps, desc="Share of requests that ended inside Kong, whichever plugin ended them."),
    stat("Signals to check", 'sum(go_live_signals{severity="warn"})', 6, y, 3, steps=warn, desc="Signals marked warn. Kinds are listed under Signals below."),
    stat("Coverage findings", f'sum(go_live_coverage_findings{{{R}}})', 9, y, 3, steps=warn,
         desc="AI routes with no guardrail, a disabled guardrail, a guardrail that peer routes have, or no probes."),
    stat("Suspected fail-open", f'sum(go_live_guardrail_fail_open_suspects{{{G}}})', 12, y, 3, steps=bad,
         desc="Allowed after about the guardrail's timeout with no decision recorded."),
    stat("Ran without a decision", f'sum(go_live_guardrail_no_verdict{{{G}}})', 15, y, 3, steps=warn),
    stat("Flagged but served", f'sum(go_live_guardrail_detected_not_enforced{{{G}}})', 18, y, 3, steps=warn,
         desc="Expected in detect-only mode; a slip if the guardrail is meant to block."),
    stat("Chain share of gateway time", f'max(go_live_chain_share{{{R}}})', 21, y, 3, unit="percentunit", decimals=0,
         steps=[{"color": "green", "value": None}, {"color": "orange", "value": 0.3}]),
]
y += 4
p.append(row("Each guardrail, now", y)); y += 1
p += [
    bars("Stopped or altered, share of requests that reached it", f'go_live_guardrail_block_rate{{{G}}}', "{{guardrail}}", 0, y, unit="percentunit",
         steps=rate_steps, maxv=1, desc="(blocked + altered) / reached. High could be an attack wave or overcatching: sample the affected requests."),
    bars("Time spent in the guardrail, p95", f'go_live_guardrail_latency_ms{{{G}, quantile="p95"}}', "{{guardrail}}", 8, y, unit="ms", steps=lat_steps,
         desc="Time between the probes on either side. Missing when two guardrails share a gap (leave a free priority between them)."),
    bars("Requests that reached it", f'go_live_guardrail_reached{{{G}}}', "{{guardrail}}", 16, y,
         desc="A guardrail later in the chain sees fewer requests: the earlier ones already stopped some."),
]
y += 7
p.append(row("Over time", y)); y += 1
p += [
    ts("Stopped or altered, per guardrail", [{"expr": f'go_live_guardrail_block_rate{{{G}}}', "legendFormat": "{{guardrail}}"}], 0, y, unit="percentunit", maxv=1,
       desc="A step up here with no config change is traffic changing; a step right after a config change is the config."),
    ts("Time spent in each guardrail, p50 and p95", [{"expr": f'go_live_guardrail_latency_ms{{{G}, quantile="p95"}}', "legendFormat": "p95 {{guardrail}}"},
                                                    {"expr": f'go_live_guardrail_latency_ms{{{G}, quantile="p50"}}', "legendFormat": "p50 {{guardrail}}"}], 12, y, unit="ms"),
]
y += 8
p += [
    ts("Suspected fail-open and silent runs", [{"expr": f'go_live_guardrail_fail_open_suspects{{{G}}}', "legendFormat": "fail-open? {{guardrail}}"},
                                              {"expr": f'go_live_guardrail_no_verdict{{{G}}} > 0', "legendFormat": "no decision {{guardrail}}"}], 0, y, w=8,
       desc="A guardrail whose backend times out and lets requests through shows here and nowhere in its own logs."),
    ts("After a block: what the same caller did next", [{"expr": f'sum by (outcome) (go_live_after_block{{{G}, outcome=~"retry_.*"}})', "legendFormat": "{{outcome}}"}], 8, y, w=8,
       desc="Retries that get through: callers rephrasing honest requests (overcatch) or stepping around the block (slip)."),
    ts("Responses and requests rewritten", [{"expr": f'sum by (guardrail, side) (go_live_guardrail_rewrites{{{G}}}) > 0', "legendFormat": "{{guardrail}} {{side}}"}], 16, y, w=8,
       desc="Body hash differs between the probes around the guardrail."),
]
y += 8
p.append(row("Routes and coverage", y)); y += 1
p += [
    ts("Requests by route (window)", [{"expr": f'go_live_requests{{{R}}}', "legendFormat": "{{route}}"}], 0, y, w=8),
    ts("Coverage findings by route", [{"expr": f'sum by (route, kind) (go_live_coverage_findings{{{R}}})', "legendFormat": "{{route}}: {{kind}}"}], 8, y, w=8,
       desc="ai_route_without_guardrail: requests reach a model with no known guardrail on the route."),
    ts("Kong responses by status (Kong's own counter)", [{"expr": 'sum by (code) (rate(kong_http_requests_total{route=~"ai-chain.*"}[1m]))', "legendFormat": "{{code}}"}], 16, y, w=8,
       unit="reqps", stack=True, desc="From Kong's prometheus plugin. A status code alone never says which plugin produced it."),
]
y += 8
p.append(row("Signals and findings", y)); y += 1
p += [
    ts("Signals by kind", [{"expr": 'sum by (kind, severity) (go_live_signals)', "legendFormat": "{{severity}} · {{kind}}"}], 0, y, w=12, stack=True, bars=True),
    ts("Tokens and streaming", [{"expr": 'go_live_tokens{type="total_tokens"}', "legendFormat": "tokens in window"},
                               {"expr": 'go_live_traffic{fact="streamed"}', "legendFormat": "streamed requests"},
                               {"expr": 'go_live_time_to_first_chunk_ms{quantile="p95"}', "legendFormat": "time to first chunk p95 (ms)"}], 12, y, w=12),
]
y += 8
p.append(logs("Findings in plain language (POST /passive/translate)", '{service_name="guardrail-evaluator", event_type="findings"}', 0, y)); y += 8

dashboard = {
    "uid": "guardrail-live", "title": "Guardrail chain - live traffic", "tags": ["kong", "guardrail", "ai", "live"], "timezone": "browser",
    "schemaVersion": 39, "version": 1, "editable": True, "refresh": "10s", "time": {"from": "now-20m", "to": "now"},
    "templating": {"list": [var("route", "Route", "label_values(go_live_requests, route)"),
                            var("guardrail", "Guardrail", "label_values(go_live_guardrail_reached, guardrail)")]},
    "panels": p,
}
out = pathlib.Path(__file__).parent / "dashboards" / "guardrail-live.json"
out.write_text(json.dumps(dashboard, indent=1))
print(f"wrote {out} ({len(p)} panels)")
