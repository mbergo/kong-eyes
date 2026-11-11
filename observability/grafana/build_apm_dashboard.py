#!/usr/bin/env python3
"""Generates dashboards/guardrail-apm.json: requests one by one, APM style, with their prompts.

Everything here is read from the evaluator's exported events in Loki: one event per request, with its status,
who stopped it, the time spent in each guardrail (from the probe trail) and, when enabled, the start of the prompt.
Prompt text needs two switches (the route's observer with capture_body_mode: bounded, and EXPORT_PROMPT_CHARS > 0 on
the evaluator); with the defaults the Prompt column stays empty and no content leaves Kong.
"""
import json
import pathlib

LOKI = {"type": "loki", "uid": "go-loki"}
PROM = {"type": "prometheus", "uid": "go-prom"}
GREEN, AMBER, RED, BLUE, PURPLE, GREY = "#3fb68b", "#f2a93b", "#e5484d", "#5b9cf5", "#d946ef", "#8b93a1"
SEL = '{service_name="guardrail-evaluator"} | event_type="kong_observation" | route=~"$route"'
_id = [0]


def nid():
    _id[0] += 1
    return _id[0]


def pos(x, y, w, h):
    return {"x": x, "y": y, "w": w, "h": h}


def steps(*pairs):
    return [{"color": c, "value": v} for v, c in pairs]


def stat(title, expr, x, y, w=4, h=4, unit="none", th=None, desc="", decimals=None):
    d = {"unit": unit, "noValue": "0", "thresholds": {"mode": "absolute", "steps": th or steps((None, BLUE))}, "color": {"mode": "thresholds"}}
    if decimals is not None:
        d["decimals"] = decimals
    return {"id": nid(), "type": "stat", "title": title, "description": desc, "datasource": LOKI, "gridPos": pos(x, y, w, h),
            "targets": [{"expr": expr, "refId": "A", "queryType": "range"}], "fieldConfig": {"defaults": d, "overrides": []},
            "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "value", "graphMode": "none", "textMode": "value",
                        "justifyMode": "center"}}


def ts(title, targets, x, y, w=12, h=8, unit="short", desc="", stack=False, bars=False, colors=None):
    custom = {"lineWidth": 2, "fillOpacity": 55 if bars else 14, "gradientMode": "none" if bars else "opacity", "lineInterpolation": "smooth",
              "showPoints": "never", "spanNulls": True, "stacking": {"mode": "normal" if stack else "none"},
              "drawStyle": "bars" if bars else "line", "barAlignment": 0, "axisBorderShow": False}
    ov = [{"matcher": {"id": "byRegexp", "options": rx}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
          for rx, c in (colors or [])]
    return {"id": nid(), "type": "timeseries", "title": title, "description": desc, "datasource": LOKI, "gridPos": pos(x, y, w, h),
            "targets": [dict(t, refId=chr(65 + i), queryType="range") for i, t in enumerate(targets)],
            "fieldConfig": {"defaults": {"unit": unit, "custom": custom, "min": 0, "color": {"mode": "palette-classic"}}, "overrides": ov},
            "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi", "sort": "desc"}}}


def col(name, props):
    return {"matcher": {"id": "byName", "options": name}, "properties": [{"id": k, "value": v} for k, v in props.items()]}


def table(title, expr, x, y, w=24, h=14, desc="", limit=200):
    text = {"type": "color-text"}
    return {"id": nid(), "type": "table", "title": title, "description": desc, "datasource": LOKI, "gridPos": pos(x, y, w, h),
            "targets": [{"expr": expr, "refId": "A", "queryType": "range", "maxLines": limit}],
            "transformations": [
                {"id": "extractFields", "options": {"source": "labels", "format": "json", "replace": False, "keepTime": False}},
                {"id": "organize", "options": {
                    "excludeByName": {k: True for k in ("labels", "labelTypes", "Line", "tsNs", "id", "model", "case_id", "detected_level", "environment", "event_id", "event_type",
                                                        "guardrail", "policy_version", "run_id", "schema_version", "scope_name", "service_name",
                                                        "severity_text", "stage", "outcome", "request_id", "synthetic", "category")},
                    "indexByName": {"Time": 0, "status": 1, "result": 2, "ms": 3, "prompt": 4, "path": 5, "caller": 6, "route": 7},
                    "renameByName": {"Time": "Time", "status": "Status", "result": "Result", "ms": "Total", "path": "Time in each plugin",
                                     "prompt": "Prompt", "caller": "Caller", "model": "Model", "route": "Route"}}},
                {"id": "convertFieldType", "options": {"conversions": [{"targetField": "Total", "destinationType": "number"},
                                                                         {"targetField": "Status", "destinationType": "number"}]}},
            ],
            "fieldConfig": {"defaults": {"custom": {"align": "left", "cellOptions": {"type": "auto"}, "filterable": True}}, "overrides": [
                col("Time", {"custom.width": 196}),
                col("Status", {"custom.width": 78, "custom.cellOptions": text, "thresholds": {"mode": "absolute", "steps": steps((None, GREEN), (400, AMBER), (500, RED))},
                               "color": {"mode": "thresholds"}}),
                col("Result", {"custom.width": 170, "custom.cellOptions": text, "mappings": [
                    {"type": "regex", "options": {"pattern": "^served$", "result": {"color": GREEN, "index": 0}}},
                    {"type": "regex", "options": {"pattern": "^stopped.*", "result": {"color": RED, "index": 1}}},
                    {"type": "regex", "options": {"pattern": "^waited.*", "result": {"color": AMBER, "index": 2}}}]}),
                col("Total", {"custom.width": 86, "unit": "ms", "custom.cellOptions": text, "color": {"mode": "thresholds"},
                              "thresholds": {"mode": "absolute", "steps": steps((None, GREY), (100, AMBER), (350, RED))}}),
                col("Time in each plugin", {"custom.width": 310}),
                col("Caller", {"custom.width": 130}), col("Route", {"custom.width": 140}),
                col("Prompt", {"custom.inspect": True}),
            ]},
            "options": {"showHeader": True, "cellHeight": "sm", "sortBy": [{"displayName": "Time", "desc": True}], "footer": {"show": False}}}


def text(md, x, y, w=24, h=3):
    return {"id": nid(), "type": "text", "title": "", "gridPos": pos(x, y, w, h), "options": {"mode": "markdown", "content": md}, "transparent": True}


def row(title, y):
    return {"id": nid(), "type": "row", "title": title, "collapsed": False, "gridPos": pos(0, y, 24, 1), "panels": []}


FIELDS = ('| json status="response.status", result="apm.result", ms="duration_ms", path="apm.path", prompt="request.prompt_excerpt", '
          'caller="consumer", model="request.model"')
REQ = f'{SEL} {FIELDS} | line_format "{{{{.prompt}}}}"'

p, y = [], 0
p.append(text("### Requests, one by one\n"
              "Every line is one request that crossed the gateway: what happened to it, how long each plugin held it, and the start of what "
              "was asked. **Served** reached the model. **Stopped by X** ended inside Kong at that plugin. **Waited at X** sat in a guardrail for "
              "about its timeout and was then let through, which is what a fail-open looks like. Click a row to filter; open a prompt cell to read it in full.",
              0, y, h=4)); y += 4
p += [
    stat("Requests per minute", f'sum(count_over_time({SEL} [1m]))', 0, y, desc="Requests seen in the last minute on the selected routes."),
    stat("Served", f'sum(count_over_time({SEL} | json src="response.source" | src!="exit" [5m])) / sum(count_over_time({SEL} [5m]))', 4, y,
         unit="percentunit", decimals=1, th=steps((None, RED), (0.5, AMBER), (0.8, GREEN)), desc="Share of requests in the last 5 minutes that reached the model."),
    stat("Stopped in the gateway", f'sum(count_over_time({SEL} | json src="response.source" | src="exit" [5m])) / sum(count_over_time({SEL} [5m]))', 8, y,
         unit="percentunit", decimals=1, th=steps((None, GREEN), (0.2, AMBER), (0.4, RED)), desc="Share of requests in the last 5 minutes that ended inside Kong."),
    stat("Gateway time, median", f'quantile_over_time(0.5, {SEL} | json ms="duration_ms" | unwrap ms | __error__="" [5m]) by ()', 12, y, unit="ms",
         th=steps((None, GREEN), (100, AMBER), (350, RED)), desc="Median time from the request entering Kong to the response leaving it, last 5 minutes."),
    stat("Gateway time, p95", f'quantile_over_time(0.95, {SEL} | json ms="duration_ms" | unwrap ms | __error__="" [5m]) by ()', 16, y, unit="ms",
         th=steps((None, GREEN), (200, AMBER), (400, RED)), desc="95 of 100 requests were faster than this, last 5 minutes."),
    stat("Waited at a guardrail", f'sum(count_over_time({SEL} | json result="apm.result" | result=~"waited.*" [5m]))', 20, y,
         th=steps((None, GREEN), (1, AMBER)), desc="Requests in the last 5 minutes that sat in a guardrail for about its timeout and were then let through."),
]
y += 4
p += [
    ts("What happened to requests, per minute", [{"expr": f'sum by (result) (count_over_time({SEL} | json result="apm.result" [1m]))', "legendFormat": "{{result}}"}],
       0, y, w=14, stack=True, bars=True, colors=[("^served$", GREEN), ("^waited.*", AMBER)],
       desc="Each bar is one minute, split by outcome. A new colour appearing is a plugin starting to stop requests."),
    ts("Gateway time", [{"expr": f'quantile_over_time(0.95, {SEL} | json ms="duration_ms" | unwrap ms | __error__="" [1m]) by ()', "legendFormat": "p95"},
                        {"expr": f'quantile_over_time(0.5, {SEL} | json ms="duration_ms" | unwrap ms | __error__="" [1m]) by ()', "legendFormat": "median"}],
       14, y, w=10, unit="ms", colors=[("p95", AMBER), ("median", BLUE)],
       desc="Kong's own time per request. The model's time is not included for the mock model, which answers instantly."),
]
y += 8
p.append(table("Latest requests", REQ, 0, y, h=16,
               desc="Newest first. 'Time in each plugin' is read from the probe trail: the time between the probes on either side of each plugin. "
                    "An x marks where the request was stopped. The Prompt column is filled only when prompt capture and export are both on; "
                    "on this demo the prompts are synthetic."))
y += 16
p.append(table("Stopped requests", REQ.replace(FIELDS, FIELDS + ' | result=~"stopped.*"'), 0, y, h=11,
               desc="Only the requests that ended inside Kong. Read a few: are these attacks, or honest requests caught by mistake?"))
y += 11

dashboard = {
    "uid": "guardrail-apm", "title": "Requests and prompts", "tags": ["kong", "guardrail", "ai", "apm"], "timezone": "browser",
    "schemaVersion": 39, "version": 1, "editable": True, "refresh": "10s", "time": {"from": "now-15m", "to": "now"},
    "links": [{"type": "dashboards", "tags": ["guardrail"], "asDropdown": False, "title": "Guardrail dashboards", "includeVars": True, "keepTime": True}],
    "templating": {"list": [{"name": "route", "label": "Route", "type": "query", "datasource": PROM,
                             "query": {"query": "label_values(go_live_requests, route)", "refId": "v"}, "definition": "label_values(go_live_requests, route)",
                             "includeAll": True, "multi": True, "refresh": 2, "sort": 1, "allValue": ".*",
                             "current": {"selected": True, "text": ["All"], "value": ["$__all"]}}]},
    "panels": p,
}
out = pathlib.Path(__file__).parent / "dashboards" / "guardrail-apm.json"
out.write_text(json.dumps(dashboard, indent=1))
print(f"wrote {out} ({len(p)} panels)")
