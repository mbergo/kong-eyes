#!/usr/bin/env python3
"""Generates dashboards/guardrail-live.json: the guardrail chain on ordinary traffic, one screen.

  build_live_dashboard.py [--embed-chain /eyes/chain]

Series are the evaluator's go_live_* gauges (recomputed over PASSIVE_WINDOW_S) plus Kong's own request
counters. --embed-chain adds the evaluator's 3D chain view as an iframe at the top; that needs Grafana
started with GF_PANELS_DISABLE_SANITIZE_HTML=true and the URL reachable by the browser (deploy/install.sh
--https sets both up). Every panel carries a description: hover the (i) next to its title.
"""
import argparse
import json
import pathlib

ap = argparse.ArgumentParser()
ap.add_argument("--embed-chain", default="", help="URL of the evaluator /chain page as the browser sees it")
args = ap.parse_args()

PROM = {"type": "prometheus", "uid": "go-prom"}
LOKI = {"type": "loki", "uid": "go-loki"}
G = 'guardrail=~"$guardrail", guardrail!="header-guardrail"'
R = 'route=~"$route"'
_id = [0]

GREEN, AMBER, RED, BLUE, TEAL, PURPLE, GREY = "#3fb68b", "#f2a93b", "#e5484d", "#5b9cf5", "#2ec4b6", "#a78bfa", "#8b93a1"


def nid():
    _id[0] += 1
    return _id[0]


def pos(x, y, w, h):
    return {"x": x, "y": y, "w": w, "h": h}


def steps(*pairs):
    return [{"color": c, "value": v} for v, c in pairs]


OK_WARN = steps((None, GREEN), (1, AMBER))
OK_BAD = steps((None, GREEN), (1, RED))
RATE = steps((None, GREEN), (0.2, AMBER), (0.4, RED))
LAT = steps((None, GREEN), (100, AMBER), (300, RED))
NEUTRAL = steps((None, BLUE))


def stat(title, expr, x, y, w=6, h=4, unit="none", th=None, desc="", decimals=None):
    d = {"unit": unit, "noValue": "0", "thresholds": {"mode": "absolute", "steps": th or NEUTRAL}, "color": {"mode": "thresholds"}}
    if decimals is not None:
        d["decimals"] = decimals
    return {"id": nid(), "type": "stat", "title": title, "description": desc, "datasource": PROM, "gridPos": pos(x, y, w, h),
            "targets": [{"expr": expr, "refId": "A"}], "fieldConfig": {"defaults": d, "overrides": []},
            "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "value", "graphMode": "area",
                        "textMode": "value", "justifyMode": "center", "wideLayout": True}}


def ts(title, targets, x, y, w=12, h=8, unit="short", desc="", stack=False, maxv=None, line_at=None, colors=None):
    custom = {"lineWidth": 2, "fillOpacity": 30 if stack else 18, "gradientMode": "opacity", "lineInterpolation": "smooth",
              "showPoints": "never", "spanNulls": True, "stacking": {"mode": "normal" if stack else "none"}, "drawStyle": "line",
              "axisBorderShow": False}
    d = {"unit": unit, "custom": custom, "min": 0, "color": {"mode": "palette-classic"}}
    if maxv is not None:
        d["max"] = maxv
    if line_at is not None:
        custom["thresholdsStyle"] = {"mode": "dashed"}
        d["thresholds"] = {"mode": "absolute", "steps": steps((None, "transparent"), (line_at, RED))}
    ov = [{"matcher": {"id": "byRegexp", "options": rx}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
          for rx, c in (colors or [])]
    return {"id": nid(), "type": "timeseries", "title": title, "description": desc, "datasource": PROM, "gridPos": pos(x, y, w, h),
            "targets": [dict(t, refId=chr(65 + i)) for i, t in enumerate(targets)], "fieldConfig": {"defaults": d, "overrides": ov},
            "options": {"legend": {"displayMode": "list", "placement": "bottom", "calcs": []}, "tooltip": {"mode": "multi", "sort": "desc"}}}


def bars(title, expr, name, x, y, w=8, h=7, unit="short", desc="", th=None, maxv=None, mode="gradient"):
    d = {"unit": unit, "min": 0, "color": {"mode": "thresholds"}, "displayName": name, "noValue": "none",
         "thresholds": {"mode": "absolute", "steps": th or NEUTRAL}}
    if maxv is not None:
        d["max"] = maxv
    return {"id": nid(), "type": "bargauge", "title": title, "description": desc, "datasource": PROM, "gridPos": pos(x, y, w, h),
            "targets": [{"expr": expr, "refId": "A", "instant": True}], "fieldConfig": {"defaults": d, "overrides": []},
            "options": {"orientation": "horizontal", "displayMode": mode, "reduceOptions": {"calcs": ["lastNotNull"]},
                        "showUnfilled": True, "valueMode": "color", "namePlacement": "left", "minVizHeight": 16, "maxVizHeight": 30,
                        "sizing": "manual", "text": {"titleSize": 13, "valueSize": 20}}}


def gauges(title, expr, name, x, y, w=8, h=7, unit="percentunit", desc="", th=None, maxv=1):
    d = {"unit": unit, "min": 0, "max": maxv, "color": {"mode": "thresholds"}, "displayName": name, "noValue": "none",
         "thresholds": {"mode": "absolute", "steps": th or RATE}}
    return {"id": nid(), "type": "gauge", "title": title, "description": desc, "datasource": PROM, "gridPos": pos(x, y, w, h),
            "targets": [{"expr": expr, "refId": "A", "instant": True}], "fieldConfig": {"defaults": d, "overrides": []},
            "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "showThresholdLabels": False, "showThresholdMarkers": True}}


def donut(title, expr, legend, x, y, w=6, h=8, desc="", colors=None):
    ov = [{"matcher": {"id": "byRegexp", "options": rx}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
          for rx, c in (colors or [])]
    return {"id": nid(), "type": "piechart", "title": title, "description": desc, "datasource": PROM, "gridPos": pos(x, y, w, h),
            "targets": [{"expr": expr, "refId": "A", "instant": True, "legendFormat": legend}],
            "fieldConfig": {"defaults": {"unit": "short", "decimals": 0, "color": {"mode": "palette-classic"}}, "overrides": ov},
            "options": {"pieType": "donut", "reduceOptions": {"calcs": ["lastNotNull"]}, "displayLabels": ["percent"],
                        "legend": {"displayMode": "table", "placement": "right", "values": ["value"]}, "tooltip": {"mode": "single"}}}


def text(content, x, y, w=24, h=2, mode="markdown", title="", transparent=True):
    return {"id": nid(), "type": "text", "title": title, "gridPos": pos(x, y, w, h), "options": {"mode": mode, "content": content},
            "transparent": transparent}


def row(title, y):
    return {"id": nid(), "type": "row", "title": title, "collapsed": False, "gridPos": pos(0, y, 24, 1), "panels": []}


def logs(title, expr, x, y, w=24, h=8, desc=""):
    return {"id": nid(), "type": "logs", "title": title, "description": desc, "datasource": LOKI, "gridPos": pos(x, y, w, h),
            "targets": [{"expr": expr, "refId": "A"}],
            "options": {"showTime": True, "wrapLogMessage": True, "prettifyLogMessage": False, "enableLogDetails": True,
                        "sortOrder": "Descending", "dedupStrategy": "none"}}


def var(name, label, query):
    return {"name": name, "label": label, "type": "query", "datasource": PROM, "query": {"query": query, "refId": "v"}, "definition": query,
            "includeAll": True, "multi": True, "refresh": 2, "sort": 1, "allValue": ".*",
            "current": {"selected": True, "text": ["All"], "value": ["$__all"]}}


HOW_TO_READ = """### How to read this

**Signals, not verdicts.** Ordinary traffic has no answer key, so nothing here proves a guardrail right
or wrong. Every number is a place to look.

| You see | It means | Look at |
|---|---|---|
| **Stopped in gateway** rises | More requests end inside Kong | Attack wave, or a guardrail overcatching |
| **Suspected fail-open** above 0 | A guardrail took about its timeout, then let the request through | That guardrail's backend |
| **Flagged but served** above 0 | It detected a problem and the client still got the answer | Is it in detect-only mode on purpose? |
| **Ran without a decision** | The guardrail ran but recorded no allow or block | Errors, or no adapter for it |
| **Coverage findings** | An AI route with no guardrail, or one its sibling routes have | Route config |
| **Retry got through** | Caller was blocked, rephrased, and passed | Overcatch (honest caller) or a slip (attacker) |

Hover the **(i)** on any panel for what it measures. Values are recomputed over a sliding window.
"""

GLOSSARY = """| Term | Meaning |
|---|---|
| **Probe** | A tiny marker plugin placed before and after each guardrail. It notes the time and a hash of the body, nothing else. |
| **Trail** | The list of probes a request passed. Where the trail stops is where the request was blocked. |
| **Gap** | The space between two neighbouring probes. One gap holds one guardrail, so time spent in the gap is that guardrail's latency. |
| **Reached** | Requests that got as far as this guardrail. Later guardrails see fewer, because earlier ones already stopped some. |
| **Stopped or altered** | (blocked + rewritten) divided by reached, for one guardrail. |
| **Chain share** | How much of the gateway's own time is spent in the guardrail chain. |
| **Window** | All live numbers cover the last few minutes (`PASSIVE_WINDOW_S`), then slide forward. |
| **Finding** | A short plain-language note written by Claude from the aggregates only. No prompts or responses are sent. |
"""

p, y = [], 0
if args.embed_chain:
    frame = (f'<iframe src="{args.embed_chain}" title="Guardrail chain" loading="lazy" '
             'style="width:100%;height:100%;border:0;border-radius:6px;background:transparent"></iframe>')
    p.append(text(frame, 0, y, w=14, h=14, mode="html", title="The chain, live: box height is p95 time in that guardrail", transparent=False))
    p.append(text(HOW_TO_READ, 14, y, w=10, h=14))
    y += 14
else:
    p.append(text(HOW_TO_READ, 0, y, w=24, h=10))
    y += 10

p.append(row("At a glance", y)); y += 1
p += [
    stat("Requests in window", f'sum(go_live_requests{{{R}}})', 0, y,
         desc="Requests the evaluator has seen on the selected routes inside the sliding window."),
    stat("Stopped in the gateway", f'sum(go_live_route_blocked{{{R}}}) / sum(go_live_requests{{{R}}})', 6, y, unit="percentunit", decimals=1, th=RATE,
         desc="Share of requests that ended inside Kong, whichever plugin ended them. Amber from 20%, red from 40%."),
    stat("Signals to check", 'sum(go_live_signals{severity="warn"})', 12, y, th=OK_WARN,
         desc="How many warn-level signals are active now. The kinds are listed under Signals below."),
    stat("Coverage findings", f'sum(go_live_coverage_findings{{{R}}})', 18, y, th=OK_WARN,
         desc="AI routes with no guardrail, a disabled guardrail, a guardrail that sibling routes have, or no probes."),
]
y += 4
p += [
    stat("Suspected fail-open", f'sum(go_live_guardrail_fail_open_suspects{{{G}}})', 0, y, th=OK_BAD,
         desc="Requests allowed after spending about the guardrail's configured timeout in it, with no decision recorded. "
              "This is what a guardrail whose backend is down looks like from outside."),
    stat("Ran without a decision", f'sum(go_live_guardrail_no_verdict{{{G}}})', 6, y, th=OK_WARN,
         desc="The guardrail executed but no allow/block verdict could be read. Either it errored or there is no adapter for it."),
    stat("Flagged but served", f'sum(go_live_guardrail_detected_not_enforced{{{G}}})', 12, y, th=OK_WARN,
         desc="The guardrail flagged the request and the client still received the response. Expected in detect-only mode; a slip otherwise."),
    stat("Chain share of gateway time", f'max(go_live_chain_share{{{R}}})', 18, y, unit="percentunit", decimals=0, th=steps((None, GREEN), (0.3, AMBER), (0.6, RED)),
         desc="Time between the first and last probe, as a share of Kong's own processing time. Model time is not included."),
]
y += 4

p.append(row("Each guardrail, right now", y)); y += 1
p += [
    gauges("Stopped or altered", f'go_live_guardrail_block_rate{{{G}}}', "${__field.labels.guardrail}", 0, y,
           desc="(blocked + altered) / reached, per guardrail. High can be an attack wave or overcatching: sample the affected requests before deciding."),
    bars("Time in the guardrail, p95", f'go_live_guardrail_latency_ms{{{G}, quantile="p95"}}', "${__field.labels.guardrail}", 8, y, unit="ms", th=LAT,
         desc="Time between the probes on either side of the guardrail. A guardrail is missing here when it shares a gap with a neighbour "
              "(leave a free priority number between them so a probe fits)."),
    bars("Requests that reached it", f'go_live_guardrail_reached{{{G}}}', "${__field.labels.guardrail}", 16, y, mode="lcd",
         desc="A guardrail later in the chain sees fewer requests because earlier ones already stopped some."),
]
y += 7

p.append(row("Over time", y)); y += 1
p += [
    ts("Stopped or altered, per guardrail", [{"expr": f'go_live_guardrail_block_rate{{{G}}}', "legendFormat": "{{guardrail}}"}], 0, y, unit="percentunit", maxv=1,
       desc="A step up with no config change is the traffic changing. A step right after a config change is the config."),
    ts("Time in each guardrail", [{"expr": f'go_live_guardrail_latency_ms{{{G}, quantile="p95"}}', "legendFormat": "p95 {{guardrail}}"},
                                 {"expr": f'go_live_guardrail_latency_ms{{{G}, quantile="p50"}}', "legendFormat": "p50 {{guardrail}}"}], 12, y, unit="ms",
       line_at=400, desc="p50 and p95 per guardrail. The dashed red line is the 400 ms timeout configured for the demo input guardrail: "
                         "p95 sitting on that line means requests are hitting the timeout."),
]
y += 8
p += [
    ts("Suspected fail-open and silent runs", [{"expr": f'go_live_guardrail_fail_open_suspects{{{G}}}', "legendFormat": "fail-open? {{guardrail}}"},
                                              {"expr": f'go_live_guardrail_no_verdict{{{G}}} > 0', "legendFormat": "no decision {{guardrail}}"}], 0, y, w=8,
       colors=[("fail-open.*", RED), ("no decision.*", AMBER)],
       desc="A guardrail whose backend times out and lets requests through shows here and nowhere in its own logs."),
    ts("After a block: what the same caller did next", [{"expr": f'sum by (outcome) (go_live_after_block{{{G}, outcome=~"retry_.*"}})', "legendFormat": "{{outcome}}"}], 8, y, w=8,
       desc="Retries that get through are either honest callers rephrasing (the block was an overcatch) or someone stepping around the guardrail (a slip)."),
    ts("Bodies rewritten", [{"expr": f'sum by (guardrail, side) (go_live_guardrail_rewrites{{{G}}}) > 0', "legendFormat": "{{guardrail}} {{side}}"}], 16, y, w=8,
       desc="The body hash differs between the probes around the guardrail: it changed the request or the response (redaction, masking)."),
]
y += 8

p.append(row("Routes and coverage", y)); y += 1
p += [
    donut("Kong responses by status", 'sum by (code) (increase(kong_http_requests_total{route=~"$route"}[$__range]))', "{{code}}", 0, y,
          colors=[("2..", GREEN), ("4..", AMBER), ("403", RED), ("5..", PURPLE)],
          desc="Kong's own counter over the dashboard time range. A status code alone never says which plugin produced it; the trail does."),
    ts("Requests by route", [{"expr": f'go_live_requests{{{R}}}', "legendFormat": "{{route}}"}], 6, y, w=9, stack=True,
       desc="Requests per route inside the sliding window."),
    ts("Coverage findings by route", [{"expr": f'sum by (route, kind) (go_live_coverage_findings{{{R}}})', "legendFormat": "{{route}}: {{kind}}"}], 15, y, w=9,
       desc="ai_route_without_guardrail means requests reach a model on a route with no known guardrail."),
]
y += 8

p.append(row("Signals and findings", y)); y += 1
p += [
    bars("Active signals by kind", 'sum by (kind) (go_live_signals) > 0', "${__field.labels.kind}", 0, y, w=8, h=8, th=steps((None, AMBER)),
         desc="Each bar is one kind of signal and how many are active. A signal is a reason to investigate, never a verdict."),
    ts("Tokens and streaming", [{"expr": 'go_live_tokens{type="total_tokens"}', "legendFormat": "tokens in window"},
                               {"expr": 'go_live_traffic{fact="streamed"}', "legendFormat": "streamed requests"},
                               {"expr": 'go_live_time_to_first_chunk_ms{quantile="p95"}', "legendFormat": "time to first chunk p95 (ms)"}], 8, y, w=8,
       desc="Traffic facts taken from Kong's AI plugins: token usage, how many requests streamed, and how long the first chunk took."),
    logs("Findings in plain language", '{service_name="guardrail-evaluator"} | event_type="findings" | json headline="headline", provider="provider" '
         '| line_format "[{{.provider}}] {{.headline}}"', 16, y, w=8,
         desc="Written by the translator (Claude API, Bedrock, or the offline stub) from the aggregates only. Open a line for the individual findings."),
]
y += 8

p.append(row("Requests, one by one", y)); y += 1
REQ = ('{service_name="guardrail-evaluator"} | event_type="kong_observation" | route=~"$route" '
       '| json status="response.status", source="response.source", blocker="exit.plugin_name", ms="duration_ms", prompt="request.prompt_excerpt" '
       '| line_format `{{.status}}  {{if eq .source "exit"}}STOPPED by {{or .blocker "?"}}{{else}}served{{end}}  {{.ms}} ms  {{.route}}  |  {{or .prompt "(prompt not exported)"}}`')
p += [
    logs("Latest requests and their prompts", REQ, 0, y, w=16, h=11,
         desc="One line per request: status, whether it was served or which plugin stopped it, gateway time, route, and the start of the prompt. "
              "Prompts appear only when two switches are on: the route's observer captures bodies (capture_body_mode: bounded) and the "
              "evaluator exports an excerpt (EXPORT_PROMPT_CHARS > 0). Both are off by default, so no content leaves Kong; the demo "
              "install turns them on because its traffic is synthetic. Open a line for the full event, including the trail."),
    logs("Stopped requests only", REQ.replace('| line_format `', '| source="exit" | line_format `'), 16, y, w=8, h=11,
         desc="The same list filtered to requests that ended inside Kong. Read a few: are these attacks, or honest requests caught by mistake?"),
]
y += 11

p.append(row("What each thing means", y)); y += 1
p.append(text(GLOSSARY, 0, y, w=24, h=9)); y += 9

dashboard = {
    "uid": "guardrail-live", "title": "Guardrail chain - live traffic", "tags": ["kong", "guardrail", "ai", "live"], "timezone": "browser",
    "schemaVersion": 39, "version": 2, "editable": True, "refresh": "10s", "time": {"from": "now-20m", "to": "now"},
    "graphTooltip": 1,
    "templating": {"list": [var("route", "Route", "label_values(go_live_requests, route)"),
                            var("guardrail", "Guardrail", "label_values(go_live_guardrail_reached, guardrail)")]},
    "panels": p,
}
out = pathlib.Path(__file__).parent / "dashboards" / "guardrail-live.json"
out.write_text(json.dumps(dashboard, indent=1))
print(f"wrote {out} ({len(p)} panels{', chain embedded' if args.embed_chain else ''})")
