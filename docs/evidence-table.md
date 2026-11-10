# Evidence availability on Kong Gateway 3.10 (verified against the 3.10.0 source tree + image 3.10.0.19)

Legend: **native** = already in `kong.log.serialize()` or a header; **observer** = added by `guardrail-observer`;
**runner** = only the test client can know it; **gap** = not obtainable, reported as `unknown`/`gaps[]`.

| Required field | Source | Phase | Versions verified | Remaining gap |
|---|---|---|---|---|
| request id | native `request.id` / `$kong_request_id`; header `X-Kong-Request-Id` | all | 3.10 | — |
| route / service / consumer | native + observer (`route.name`, `consumer.username`) | access | 3.10 | — |
| timestamps per phase | observer `phases.{access,header_filter,log}.ts_ms` | access→log | 3.10 | nginx pre-access time not included |
| native latencies | native `latencies.{kong,proxy,request}` | log | 3.10 | — |
| which plugins ran, per phase, with timing | Kong request-debug trace `ngx.ctx.req_trace_ctx` → observer `request_debug` | log | 3.10 (needs `X-Kong-Request-Debug: *` + token, request_debug=on) | passive traffic without the header has no trace |
| which plugins have downstream handlers on this request | observer `plugin_chain` from `ctx.plugins` (internal) | log | 3.10 | access-only plugins (auth) not listed |
| plugins configured for the route/service/global | observer `configured_plugins` via `kong.db.plugins` + cache, config sha256 | log | 3.10 | scan capped at 2000 plugin rows (`truncated` flag) |
| which plugin short-circuited (exit attribution) | observer `exit` from request-debug trace (high) or AI filter chain (medium) | log | 3.10 | none without trace & non-AI exiter → `exit_without_attribution` |
| ai-prompt-guard verdict | observer adapter `ai-prompt-guard@1`: `ai_executed_filters["guard-prompt"]`, `ai_namespaced_ctx["guard-prompt"].guarded`, exit 400/500 | log | 3.10 (file `kong/plugins/ai-prompt-guard/filters/guard-prompt.lua`) | plugin logs no verdict itself; on other versions adapter reports `unknown` |
| ai-proxy model / provider / tokens / latency | native `ai.proxy.meta|usage` (needs `logging.log_statistics`) + observer `ai.model`, `ai.metrics` | body_filter→log | 3.10 | tokens require provider usage block |
| was a model call dispatched | observer `upstream.ai_proxy_request_normalized` + `ai_response_body_present` + `kong_proxied` | log | 3.10 | ai-proxy does not mark the HTTP call explicitly → evaluator reports `None` when ambiguous |
| upstream attempts / retries | native `tries` + observer `attempts` (`ctx.balancer_data.tries`) | log | 3.10 | AI provider retries inside ai-proxy-advanced not visible |
| response status / source (`service|exit|error`) | observer `response.{status,source}` via PDK | header_filter, log | 3.10 | — |
| pre-transform response bytes (hash, size, chunk timeline) | observer `stream.*` at priority 790 | body_filter | 3.10 | **not** client-visible bytes |
| post-transform response bytes | `guardrail-observer-tail` `tail.*` at priority 5 | body_filter | 3.10 | last plugin-visible; still not proof of client bytes |
| client-received bytes, chunk timing, marker presence | **runner** observation | — | — | required for every enforcement/delivery claim |
| output guardrail verdict + pre-enforcement evidence | ctx-events contract (`ngx.ctx.guardrail_events`) or `response-header` adapter | body_filter/log | contract v1 | enterprise guardrails without an adapter → `unknown` |
| gzip: request `Accept-Encoding` vs response `Content-Encoding` | observer `request.accept_encoding`, `response.content_encoding` | access, header_filter | 3.10 | — (explains output guards that inspect compressed bytes) |
| expected policy action / label provenance | **runner → evaluator** labels (never sent to Kong) | — | — | — |
| trusted correlation (run/case/trial) | observer `runner.*` from HMAC-signed header | access | 3.10 | unsigned/invalid → `trusted=false`, never joined |
| clock skew gateway↔runner | observer `runner.skew_ms` (gateway clock − signed runner timestamp) | access | 3.10 | includes one-way network latency |
| tool/agent execution outcome | **gap** | — | — | gateway telemetry cannot prove a local tool ran; evaluator marks action-level claims `unknown` |

## Native log plugins compared

`http-log` is used because it: batches (`queue.max_batch_size`), retries with backoff (`max_retry_time`),
carries basic-auth userinfo for the evaluator token, and its serialized event already contains every
`kong.log.set_serialize_value` enrichment made by plugins of **higher** priority in the `log` phase
(observer = 790, http-log = 12). `file-log`/`tcp-log`/`opentelemetry` would carry the same fields; OTLP
from Kong's `opentelemetry` plugin exports traces/metrics, not the serialized log body, so it is not a
substitute for the evidence event.

Queue facts (kong/tools/queue.lua): worker-local memory, lost on worker exit; capacity `max_entries`
(default 10000) / `max_bytes`; delivery is at-least-once (retries) → the evaluator deduplicates on
`event_id`. Undelivered batches show up as `runner_without_kong` in `/unmatched`.
