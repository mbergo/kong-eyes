#!/usr/bin/env python3
"""Generates dashboards/guardrail-observer.json. Run after changing panel definitions.
Definitions mirror observability/splunk/searches.spl so both UIs show the same totals."""
import json
import pathlib

PROM = {"type": "prometheus", "uid": "go-prom"}
LOKI = {"type": "loki", "uid": "go-loki"}
SCOPE = 'environment=~"$environment", route=~"$route", guardrail=~"$guardrail", policy_version=~"$policy_version", suite=~"$suite"'
LOKI_SEL = '{service_name="guardrail-evaluator", environment=~"$environment", route=~"$route", guardrail=~"$guardrail", stage=~"$stage", category=~"$category"'

_id = [0]


def nid():
    _id[0] += 1
    return _id[0]


def stat(title, expr, x, y, w=4, h=4, unit="none", no_value="no data", thresholds=None, desc="", instant=True, ds=PROM, decimals=None):
    t = thresholds or [{"color": "text", "value": None}]
    p = {"id": nid(), "type": "stat", "title": title, "description": desc, "datasource": ds,
         "gridPos": {"x": x, "y": y, "w": w, "h": h},
         "targets": [{"refId": "A", "expr": expr, "instant": instant, "range": not instant, "datasource": ds}],
         "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "colorMode": "value",
                     "graphMode": "none", "textMode": "value", "justifyMode": "center"},
         "fieldConfig": {"defaults": {"unit": unit, "noValue": no_value, "thresholds": {"mode": "absolute", "steps": t}}, "overrides": []}}
    if decimals is not None:
        p["fieldConfig"]["defaults"]["decimals"] = decimals
    return p


def ts(title, targets, x, y, w=12, h=8, unit="short", desc="", ds=PROM, stack=False):
    return {"id": nid(), "type": "timeseries", "title": title, "description": desc, "datasource": ds,
            "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [dict({"refId": chr(65 + i), "datasource": ds}, **t) for i, t in enumerate(targets)],
            "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}},
            "fieldConfig": {"defaults": {"unit": unit, "custom": {"stacking": {"mode": "normal" if stack else "none"}, "fillOpacity": 15 if stack else 0}},
                            "overrides": []}}


def text(title, md, x, y, w=24, h=3):
    return {"id": nid(), "type": "text", "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "options": {"mode": "markdown", "content": md}}


def row(title, y):
    return {"id": nid(), "type": "row", "title": title, "collapsed": False, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []}


def logs(title, expr, x, y, w=24, h=10):
    return {"id": nid(), "type": "logs", "title": title, "datasource": LOKI, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [{"refId": "A", "expr": expr, "datasource": LOKI}],
            "options": {"showTime": True, "wrapLogMessage": True, "prettifyLogMessage": True, "enableLogDetails": True, "sortOrder": "Descending"}}


def table_cases(x, y):
    expr = (LOKI_SEL + ', event_type="adjudication"} | json case_id="case_id", trial="trial", expected="expected.action", '
            'violation="expected.violation", verdict="verdict.value", detector="detector.outcome", enforcement="enforcement.outcome", '
            'delivery="delivery.outcome", policy="policy.outcome", client_status="client.status", request_id="request_id", '
            'run_id="run_id", revision="adjudication_revision" | line_format "{{.case_id}}"')
    return {"id": nid(), "type": "table", "title": "Case drill-down (adjudications, newest revision first) - expected vs verdict vs delivery",
            "description": "Loki keeps every revision; filter by run_id and take the highest revision per case. Click a row's request_id to pivot into kong_observation events.",
            "datasource": LOKI, "gridPos": {"x": x, "y": y, "w": 24, "h": 12},
            "targets": [{"refId": "A", "expr": expr, "datasource": LOKI, "queryType": "range", "maxLines": 500}],
            "transformations": [{"id": "extractFields", "options": {"source": "labels", "replace": False}},
                                {"id": "organize", "options": {"excludeByName": {"Line": True, "labels": True, "id": True, "tsNs": True, "Time": False},
                                                               "indexByName": {"Time": 0, "run_id": 1, "revision": 2, "case_id": 3, "trial": 4, "guardrail": 5, "stage": 6,
                                                                               "expected": 7, "violation": 8, "verdict": 9, "detector": 10, "enforcement": 11,
                                                                               "delivery": 12, "policy": 13, "client_status": 14, "request_id": 15}}}],
            "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}}}


def var(name, label, query, ds=PROM, include_all=True, multi=True):
    return {"name": name, "label": label, "type": "query", "datasource": ds, "query": {"query": query, "refId": "v"} if ds is PROM else {"label": name, "type": 1},
            "definition": query, "includeAll": include_all, "multi": multi, "refresh": 2, "sort": 1,
            "current": {"selected": True, "text": ["All"], "value": ["$__all"]}, "allValue": ".*"}


panels = []
y = 0
panels.append(text("Read me first", (
    "**Adjudicated** panels are recomputed gauges over the *newest revision of the newest finalized run per scope* "
    "(environment, route, guardrail, policy_version, suite). Label corrections lower numbers; nothing here is an ever-increasing counter.  \n"
    "**FPR = FP/(FP+TN)**, **FNR = FN/(FN+TP)**; shown as *N/A* when the denominator is 0. **Missing data is shown as `no data`, never as 0 errors.**  \n"
    "Results on a curated, attack-heavy suite are **benchmark numbers, not production rates**. `synthetic=1` means the guardrail under test is a fixture.  \n"
    "Detector accuracy (TP/FP/FN/TN), enforcement (did a detected violation still reach the client?) and delivery (what the client got) are separate columns on purpose: "
    "a model refusal is not a guardrail block, and an HTTP status is not a verdict."), 0, y))
y += 3
panels.append(row("Live traffic - signals to investigate (ordinary requests, no labels)", y)); y += 1
orange = [{"color": "green", "value": None}, {"color": "orange", "value": 1}]
red = [{"color": "green", "value": None}, {"color": "red", "value": 1}]
panels.append(text("How to read this row", (
    "Computed from the probe trail on ordinary traffic over the evaluator's window (`PASSIVE_WINDOW_S`, default 15 min). "
    "**Nothing here is a verdict**: without labels a block cannot be called wrong, only unusual. Each number is a place to look. "
    "The same data with the evidence behind it: evaluator `/passive/summary`; drawn as a chain: evaluator `/chain`."), 0, y, h=2)); y += 2
panels += [
    stat("Signals (warn)", 'sum(go_live_signals{severity="warn"})', 0, y, thresholds=orange, no_value="0", desc="Signals marked warn in the window. See the table below for which."),
    stat("Coverage findings", 'sum(go_live_coverage_findings{route=~"$live_route"})', 4, y, thresholds=orange, no_value="0",
         desc="AI routes with no guardrail, a disabled guardrail, a guardrail present on peer routes but not here, or no probes."),
    stat("Suspected fail-open", 'sum(go_live_guardrail_fail_open_suspects{guardrail=~"$live_guardrail"})', 8, y, thresholds=red, no_value="0",
         desc="Requests allowed after spending about the guardrail's configured timeout in its gap, with no decision recorded."),
    stat("Ran without a decision", 'sum(go_live_guardrail_no_verdict{guardrail=~"$live_guardrail"})', 12, y, thresholds=orange, no_value="0",
         desc="The guardrail's position was reached but it recorded no verdict."),
    stat("Flagged but still served", 'sum(go_live_guardrail_detected_not_enforced{guardrail=~"$live_guardrail"})', 16, y, thresholds=orange, no_value="0",
         desc="Expected in detect-only mode; a slip if the guardrail is meant to block."),
    stat("Guardrail config changes", 'sum(go_live_config_changes{route=~"$live_route"})', 20, y, thresholds=orange, no_value="0",
         desc="Changes of the guardrail config fingerprint seen in the window. Compare block rate before and after in /passive/summary."),
]
y += 4
panels += [
    ts("Share of requests stopped or altered, per guardrail", [{"expr": 'go_live_guardrail_block_rate{guardrail=~"$live_guardrail"}', "legendFormat": "{{guardrail}}", "instant": False}],
       0, y, w=8, unit="percentunit", desc="(blocked + altered) / reached. A jump is either an attack wave or overcatching: sample the affected requests."),
    ts("Time spent in each guardrail (p95)", [{"expr": 'go_live_guardrail_latency_ms{guardrail=~"$live_guardrail", quantile="p95"}', "legendFormat": "{{guardrail}}", "instant": False}],
       8, y, w=8, unit="ms", desc="Timestamp difference between the probes on either side of the guardrail. Missing for guardrails that share a gap."),
    ts("Guardrail chain share of gateway time (median)", [{"expr": 'go_live_chain_share{route=~"$live_route"}', "legendFormat": "{{route}}", "instant": False}],
       16, y, w=8, unit="percentunit"),
]
y += 8
panels += [
    ts("After a block: what the same caller did next", [{"expr": 'sum by (guardrail, outcome) (go_live_after_block{guardrail=~"$live_guardrail", outcome=~"retry_.*"})',
                                                         "legendFormat": "{{guardrail}} {{outcome}}", "instant": False}], 0, y, w=8,
       desc="Retries that get through after a block: callers rephrasing honest requests (overcatch) or stepping around the block (slip)."),
    ts("Bodies rewritten across a guardrail", [{"expr": 'sum by (guardrail, side) (go_live_guardrail_rewrites{guardrail=~"$live_guardrail"})', "legendFormat": "{{guardrail}} {{side}}", "instant": False}], 8, y, w=8,
       desc="Hash of the request (or response) differs between the probes around the guardrail."),
    ts("Signals by kind", [{"expr": 'sum by (kind, severity) (go_live_signals)', "legendFormat": "{{severity}} {{kind}}", "instant": False}], 16, y, w=8),
]
y += 8
panels += [
    ts("Coverage findings by route", [{"expr": 'sum by (route, kind) (go_live_coverage_findings{route=~"$live_route"})', "legendFormat": "{{route}} {{kind}}", "instant": False}], 0, y, w=8),
    ts("Streaming: time to first chunk", [{"expr": 'go_live_time_to_first_chunk_ms', "legendFormat": "{{quantile}}", "instant": False}], 8, y, w=8, unit="ms"),
    ts("Tokens and request facts in the window", [{"expr": 'go_live_tokens', "legendFormat": "{{type}}", "instant": False},
                                                  {"expr": 'go_live_traffic{fact=~"retried|upstream_errors|model_mismatch|streamed"}', "legendFormat": "{{fact}}", "instant": False}], 16, y, w=8),
]
y += 8
panels.append(logs("Findings in plain language (POST /passive/translate; Claude API, Bedrock, or the offline translator)",
                   '{service_name="guardrail-evaluator", event_type="findings"}', 0, y, h=8)); y += 8
panels.append(row("Adjudicated results - latest run per scope", y)); y += 1
C = f'sum(go_eval_units{{{SCOPE}, outcome="%s"}})'
red = [{"color": "green", "value": None}, {"color": "red", "value": 1}]
panels += [
    stat("True positives (violation flagged)", C % "TP", 0, y, desc="Violations the guardrail flagged."),
    stat("False positives (benign flagged)", C % "FP", 4, y, thresholds=red, desc="Overcatching at the detector level."),
    stat("False negatives (violation missed)", C % "FN", 8, y, thresholds=red, desc="Let-slip at the detector level."),
    stat("True negatives (benign passed)", C % "TN", 12, y),
    stat("Inconclusive / excluded / error", f'sum(go_eval_units{{{SCOPE}, outcome=~"INCONCLUSIVE|EXCLUDED|ERROR"}})', 16, y,
         thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}], desc="Units with no matrix classification (missing verdict, not_run, unrelated failure, timeout). Never counted as TN."),
    stat("Labeled coverage", f'avg(go_eval_labeled_coverage{{{SCOPE}}})', 20, y, unit="percentunit", decimals=0, desc="Share of units that got a binary classification."),
]
y += 4
panels += [
    stat("FPR = FP/(FP+TN)", f'avg(go_eval_fpr{{{SCOPE}}})', 0, y, unit="percentunit", decimals=1, no_value="N/A", thresholds=red,
         desc="Omitted by the evaluator when FP+TN = 0 -> shows N/A."),
    stat("FP denominator (FP+TN)", f'sum(go_eval_fpr_denominator{{{SCOPE}}})', 4, y),
    stat("FNR = FN/(FN+TP)", f'avg(go_eval_fnr{{{SCOPE}}})', 8, y, unit="percentunit", decimals=1, no_value="N/A", thresholds=red,
         desc="Omitted by the evaluator when FN+TP = 0 -> shows N/A."),
    stat("FN denominator (FN+TP)", f'sum(go_eval_fnr_denominator{{{SCOPE}}})', 12, y),
    stat("Confirmed enforcement failures", f'sum(go_eval_enforcement_failures{{{SCOPE}}})', 16, y, thresholds=red,
         desc="Detected violations that still reached the client (detect-only mode, late stream abort, dispatched to model)."),
    stat("Benign blocked or altered", f'sum(go_eval_benign_blocked{{{SCOPE}}})', 20, y, thresholds=red, desc="Client-visible overcatch damage (separate from FP count)."),
]
y += 4
panels += [
    stat("Violations delivered to client", f'sum(go_eval_violations_delivered{{{SCOPE}}})', 0, y, thresholds=red),
    stat("Manifest reconciled", f'min(go_eval_manifest_reconciled{{{SCOPE}}})', 4, y, no_value="unknown",
         thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}], desc="1 when adjudicated units == runner manifest."),
    stat("Adjudication revision", f'max(go_eval_revision{{{SCOPE}}})', 8, y),
    stat("Synthetic fixture under test?", f'max(go_eval_synthetic{{{SCOPE}}})', 12, y, thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
         desc="1 = results come from a deliberately faulty fixture guardrail used to validate the evaluator."),
    ts("Units by category and outcome", [{"expr": f'sum by (category, outcome) (go_eval_units_by_category{{{SCOPE}, outcome=~"TP|FP|FN|TN"}})',
                                          "legendFormat": "{{category}} {{outcome}}", "instant": False}], 16, y, w=8, h=4),
]
y += 4
panels.append(row("Traffic volume, guardrail actions and stages (all observed requests, labeled or not)", y)); y += 1
panels += [
    ts("Observed requests by guardrail verdict", [{"expr": f'sum by (outcome) (count_over_time({LOKI_SEL}, event_type="kong_observation"}}[$__auto]))',
                                                   "legendFormat": "{{outcome}}", "queryType": "range"}], 0, y, ds=LOKI, stack=True,
       desc="Verdict announced by the observer adapters (allow/deny/detect/not_run/unknown). Passive traffic shows actions and coverage only - never FP/FN rates."),
    ts("Observed requests by route and stage", [{"expr": f'sum by (route, stage) (count_over_time({LOKI_SEL}, event_type="kong_observation"}}[$__auto]))',
                                                 "legendFormat": "{{route}} / {{stage}}", "queryType": "range"}], 12, y, ds=LOKI, stack=True),
]
y += 8
panels += [
    ts("Kong proxy requests (native prometheus plugin)", [{"expr": 'sum by (route, code) (rate(kong_http_requests_total[$__rate_interval]))',
                                                           "legendFormat": "{{route}} {{code}}", "instant": False}], 0, y,
       desc="From Kong's bundled prometheus plugin scraped on :8100. Status codes alone never prove allow/block."),
    ts("Evidence gaps per request (observer-reported)", [{"expr": f'sum by (outcome) (count_over_time({LOKI_SEL}, event_type="kong_observation"}} | json | gaps != "[]" [$__auto]))',
                                                          "legendFormat": "with gaps ({{outcome}})", "queryType": "range"}], 12, y, ds=LOKI,
       desc="Requests whose observation lists at least one gap (request body in file, exit without attribution, adapter error...)."),
]
y += 8
panels.append(row("Latency and observer overhead", y)); y += 1
panels += [
    ts("Gateway duration (observer access->log), p50/p95/p99",
       [{"expr": 'histogram_quantile(0.5, sum by (le, route) (rate(go_gateway_duration_ms_bucket{route=~"$route"}[$__rate_interval])))', "legendFormat": "p50 {{route}}", "instant": False},
        {"expr": 'histogram_quantile(0.95, sum by (le, route) (rate(go_gateway_duration_ms_bucket{route=~"$route"}[$__rate_interval])))', "legendFormat": "p95 {{route}}", "instant": False},
        {"expr": 'histogram_quantile(0.99, sum by (le, route) (rate(go_gateway_duration_ms_bucket{route=~"$route"}[$__rate_interval])))', "legendFormat": "p99 {{route}}", "instant": False}],
       0, y, unit="ms", desc="Measured inside Kong by the observer: first access handler (priority 790) to log phase. Excludes client<->Kong network and nginx pre-access time."),
    ts("Client latency (runner), p50/p95",
       [{"expr": 'histogram_quantile(0.5, sum by (le, route) (rate(go_client_latency_ms_bucket{route=~"$route"}[$__rate_interval])))', "legendFormat": "p50 {{route}}", "instant": False},
        {"expr": 'histogram_quantile(0.95, sum by (le, route) (rate(go_client_latency_ms_bucket{route=~"$route"}[$__rate_interval])))', "legendFormat": "p95 {{route}}", "instant": False}],
       12, y, unit="ms", desc="Measured by the runner: request sent to last byte received, including the model."),
]
y += 8
panels.append(text("Observer overhead - measurement boundary", (
    "Overhead is measured by **A/B routes** in `scripts/perf.sh` (identical route with and without the observer plugins), reported as the "
    "difference of client-side p50/p95 and of Kong's own `kong_request_latency_ms`/`kong_kong_latency_ms`. In-band numbers above include the model and cannot isolate the observer."), 0, y))
y += 3
panels.append(row("Pipeline health - telemetry gaps", y)); y += 1
panels += [
    ts("Ingestion (events/s)", [{"expr": 'sum by (source, result) (rate(go_ingest_events_total[$__rate_interval]))', "legendFormat": "{{source}} {{result}}", "instant": False}], 0, y, w=8),
    ts("Export outbox by destination/status", [{"expr": 'sum by (destination, status) (go_outbox_events)', "legendFormat": "{{destination}} {{status}}", "instant": False}], 8, y, w=8,
       desc="pending/failed growing = destination outage. Queues are independent per destination."),
    ts("Unmatched observations after join timeout", [{"expr": 'sum by (side) (go_unmatched_observations)', "legendFormat": "{{side}}", "instant": False}], 16, y, w=8,
       desc="kong_without_runner: gateway saw a signed test request the runner never reported. runner_without_kong: http-log batch lost/late (worker-local queue, not durable)."),
]
y += 8
panels.append(row("Case drill-down", y)); y += 1
panels.append(table_cases(0, y)); y += 12
panels.append(logs("Adjudication events (full evidence JSON)", LOKI_SEL + ', event_type="adjudication"}', 0, y)); y += 10
panels.append(logs("Kong observations (phase trace, exit attribution, stream timeline)", LOKI_SEL + ', event_type="kong_observation"} |= "$request_id"', 0, y)); y += 10

dashboard = {
    "uid": "guardrail-observer", "title": "Guardrail Observer - overcatch, let-slip, enforcement", "tags": ["kong", "guardrail", "ai"],
    "timezone": "browser", "schemaVersion": 39, "version": 1, "editable": True, "refresh": "30s", "time": {"from": "now-6h", "to": "now"},
    "templating": {"list": [
        var("environment", "Environment", "label_values(go_eval_units, environment)"),
        var("route", "Route", "label_values(go_eval_units, route)"),
        var("guardrail", "Guardrail", "label_values(go_eval_units, guardrail)"),
        var("policy_version", "Policy version", "label_values(go_eval_units, policy_version)"),
        var("category", "Category", "label_values(go_eval_units_by_category, category)"),
        var("suite", "Suite", "label_values(go_eval_units, suite)"),
        var("live_route", "Live route", "label_values(go_live_requests, route)"),
        var("live_guardrail", "Live guardrail", "label_values(go_live_guardrail_reached, guardrail)"),
        {"name": "stage", "label": "Stage", "type": "custom", "query": "input,output", "includeAll": True, "multi": True, "allValue": ".*",
         "current": {"selected": True, "text": ["All"], "value": ["$__all"]}, "options": [
             {"text": "All", "value": "$__all", "selected": True}, {"text": "input", "value": "input", "selected": False}, {"text": "output", "value": "output", "selected": False}]},
        {"name": "request_id", "label": "Request id (drill-down)", "type": "textbox", "query": "", "current": {"text": "", "value": ""}},
    ]},
    "panels": panels,
}

out = pathlib.Path(__file__).parent / "dashboards" / "guardrail-observer.json"
out.write_text(json.dumps(dashboard, indent=1))
print(f"wrote {out} ({len(panels)} panels)")
