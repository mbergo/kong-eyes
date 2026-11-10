# Event schema (schema_version 1.0)

Three event types, all JSON, all carrying `event_id` (stable, dedup key) and `schema_version`.

## `kong_observation` — produced by the observer inside Kong, shipped by http-log, normalized by the evaluator

| field | meaning |
|---|---|
| `event_id` | sha256(request_id, route id, access ts)[:32] — identical on http-log retries |
| `request_id`, `started_at_ms`, `ended_at_ms`, `duration_ms` | correlation + observer-measured duration (access→log) |
| `environment`, `policy_version`, `policy_fingerprint` | operator label; sha of the guardrail plugin configs on the route |
| `route`, `service`, `consumer` | names/ids |
| `runner` | `{present, trusted, reason, run_id, case_id, trial, sent_at_ms, skew_ms}` — only `trusted=true` is joined |
| `request` | method, path, content_type, accept_encoding, body_bytes, body_sha256, stream_requested, model, message_count, roles, prompt_chars, json_valid, body_in_file, [body_prefix if capture=bounded] |
| `response` | status, source (`service|exit|error`), content_type, content_encoding, transfer_encoding, proxied, upstream_status, kong_unexpected |
| `exit` | `{plugin_name, plugin_id, instance_name, status, attribution, confidence, executed_access_plugins[]}` when `response.source == "exit"` |
| `guardrails[]` | adapter records: guardrail, adapter, stage, verdict, mode, action, enforced_by, status, provenance, supported, reason, confidence, ts_ms, seq, evidence |
| `upstream` | kong_proxied, upstream_status, ai_proxy_request_normalized, ai_response_body_present, ai_response_body_source, latencies_ms |
| `attempts[]` | balancer tries (ip, port, code, state, balancer_latency) |
| `request_debug` | Kong's request-debug trace: phases → plugins (name, plugin_id, priority, total_time_ms) |
| `plugin_chain[]`, `configured_plugins` | collected downstream handlers; applicable plugin instances with `config_sha256` |
| `ai` | executed_filters[], namespaces[], stream_mode, model, response_body_bytes/sha256/source, metrics (llm_*), request_body_source |
| `stream`, `tail` | chunks, bytes, sha256, first_chunk_at_ms, eof_at_ms, timeline[{t,n}], truncated, observed_at, [body_prefix] |
| `capture` | body_mode, max_capture_bytes, max_chunks_recorded, metadata_only |
| `gaps[]` | missing-evidence reasons |
| `native`, `ai_native`, `guardrail_fixture_native` | selected native Kong fields, `ai.<plugin>.meta/usage`, fixture events as written to the log |

### Added in schema 1.1

| field | meaning |
|---|---|
| `trail` | probe trail: `request[]`, `gaps[]`, `missing[]`, `exit`, `response[]`, `response_gaps[]`, `probes_expected[]` (see `docs/probes.md`) |
| `exit.probe_trail` | the trail's own answer (`plugin_name`, `candidates`, `confidence`, `ms`), kept next to whichever attribution won |
| `guardrails_configured[]` | known guardrail plugins on the route: name, enabled, priority, config hash |
| `thresholds.guardrail_timeouts_ms` | per-guardrail timeout used by the fail-open check |

## `findings` — produced by `POST /passive/translate`

`{event_id, ts, provider, headline, findings[{title, severity, guardrail, route, observed, could_mean, next_check, based_on[], status: "investigate"}]}`

## `adjudication` — produced by the evaluator per (run, case, trial, guardrail, stage, revision)

| field | meaning |
|---|---|
| `event_id` | sha256(run_id, case_id, trial, guardrail, stage, revision)[:32] — new id per revision |
| `run_id`, `case_id`, `trial`, `guardrail`, `stage`, `adjudication_revision`, `mode` | evaluation unit |
| `request_id`, `attempt_id`, `attempts` | gateway correlation (latest attempt adjudicated; all attempts in drill-down) |
| `expected` | `{action, violation, stage, category, label_source, label_confidence, disputed}` |
| `verdict` | `{value, mode, action, enforced_by, provenance, adapter, reason, supported, evidence}` |
| `detector` | `{outcome: TP|FP|FN|TN|INCONCLUSIVE|EXCLUDED|ERROR|N/A, reason, flagged}` |
| `enforcement` | `{outcome: ENFORCED|ENFORCEMENT_FAILURE|NOT_ENFORCED_NO_LEAK_OBSERVED|UNKNOWN|N/A, reason, leaked_chunks, timing}` |
| `delivery` | `{outcome: BENIGN_DELIVERED|BENIGN_BLOCKED|BENIGN_ALTERED|VIOLATION_PREVENTED|VIOLATION_DELIVERED|TRANSFORM_OK|TRANSFORM_WRONG|CLIENT_ERROR|UPSTREAM_OR_GATEWAY_ERROR|UNRELATED_FAILURE|UNKNOWN, reason, status}` |
| `policy` | `{outcome: PASS|FAIL|PASS_BY_OTHER_MEANS|PASS_WITH_FALSE_POSITIVE|INCONCLUSIVE, reason}` |
| `model` | dispatched, answered, emitted_violation_marker, refusal_like — kept apart from the guardrail |
| `gateway`, `client` | compact copies of the two evidence sides |
| `clock_skew_ms`, `gaps[]`, `notes[]`, `synthetic`, `category`, `environment`, `route`, `policy_version` | |

## `smoke_test` — connection test: `{smoke_id, message, ts}`

## Deduplication and revisions

- `kong_observation`: SQLite primary key on `event_id`; a replayed http-log batch increments
  `go_ingest_events_total{result="duplicate"}` and changes nothing.
- `adjudication`: every re-adjudication (finalize, relabel) writes a **new revision** with a new
  `event_id`; destinations keep all revisions, so dashboards must select `max(adjudication_revision)` per
  unit (the provided SPL and Grafana panels do). Prometheus gauges are recomputed from the latest revision.
- Export outbox: `UNIQUE(destination, event_id)`; each destination has its own retry state.
