# Phase trace: how plugins actually run on Kong 3.10 and what the observer records

Verified in `kong/runloop/plugins_iterator.lua` and `kong/init.lua` (3.10.0) and reproduced at runtime on
`kong/kong-gateway:3.10.0.19` with Kong's own request-debug trace.

## Ordering facts that matter

1. **Every phase runs plugins in descending `PRIORITY`.** Response-side handlers (`header_filter`,
   `body_filter`, `log`) are *not* reversed. Observer (790) therefore sees the response before
   ai-proxy (770) and before any output guardrail with a lower priority; the tail plugin (5) sees it after.
2. **Downstream handlers are collected during `access`.** `get_next_and_collect` walks all plugins in
   priority order; for each one with a configuration it registers its `header_filter/body_filter/log`
   handlers *whether or not its `access` handler gets to run*.
3. **A `kong.response.exit()` in `access` does not stop the collection.** `execute_collecting_plugins_iterator`
   keeps iterating but skips the remaining `access` handlers (`if not ctx.delayed_response`). Consequence,
   observed on the real `pg-viol-001` case:
   - access executed: `key-auth → guardrail-observer → ai-prompt-guard` (exit 400) — ai-proxy's access never ran;
   - yet ai-proxy's `header_filter/body_filter/log` filters ran (`normalize-response-header`, `parse-sse-chunk`, …);
   - `http-log` (12) still logs the request. This is why a blocked request still produces evidence.
4. **A `response` handler forces buffered proxying** (`ctx.buffered_proxying = true` during collection).
   The observer deliberately has none.
5. **Plugins whose `access` runs before 790** (auth ≥ 1000, rate-limiting 910, ip-restriction 990, …) can reject
   the request before the observer exists on it → no gateway evidence. The evaluator classifies those units
   as `EXCLUDED: rejected_before_observer` from the runner's status, never as TN.
6. **`request-termination` has priority 2**, i.e. it runs *after* every AI plugin's access. A guardrail on the
   same route still produces its verdict first (verified by `short-circuit.yaml`).
7. The AI plugin framework (`kong/llm/plugin/base.lua`) executes filters by *stage* inside each phase and
   marks `ngx.ctx.ai_executed_filters[name] = true`. `ai-prompt-guard`'s filter `guard-prompt` sets
   `ngx.ctx.ai_namespaced_ctx["guard-prompt"].guarded = true` only on allow and `kong.response.exit(400)` on deny.

## What a `kong_observation` event carries (trace-related)

```
request_debug.phases.access.plugins[]   {name, plugin_id, priority, total_time_ms}  ← Kong's own trace, in execution order
request_debug.phases.{rewrite,header_filter,body_filter,log,upstream,response}      ← timings
exit        {plugin_name, plugin_id, status, attribution: request-debug-trace|ai-filter-chain|unavailable, confidence}
plugin_chain[]        plugins with collected downstream handlers (name, priority, phases)
configured_plugins    every plugin instance applicable to the route (name, scope, enabled, config_sha256)
ai.executed_filters[] AI framework filters that ran; ai.stream_mode; ai.response_body_source
upstream              kong_proxied, upstream_status, ai_proxy_request_normalized, ai_response_body_present
stream / tail         chunk counts, bytes, sha256, per-chunk timeline (bounded), observed_at label
gaps[]                anything missing: no_request_debug_trace, exit_without_attribution, request_body_in_file, …
```

## How the trace is obtained

Kong's request debugging (`request_debug = on`, default) activates when the request carries
`X-Kong-Request-Debug: *` and, unless from loopback, `X-Kong-Request-Debug-Token: <request_debug_token>`.
Kong strips these headers before plugins run and builds `ngx.ctx.req_trace_ctx`; the observer reads it in
its `log` phase. The runner sends the headers (`KONG_REQUEST_DEBUG_TOKEN`) and also stores Kong's
`X-Kong-Request-Debug-Output` response header as client-side evidence. Passive traffic without the header
has no trace: exit attribution then falls back to the AI filter chain (medium confidence) or is reported
as a gap. No global function is monkeypatched: wrapping `kong.response.exit` was tested and breaks the
Admin API's content-phase exit handling on 3.10.0.19.

## Measured on 3.10.0.19 (local, mock model)

- Observer + tail overhead: p50 within ±0.6 ms of an identical route without them (N=100–150; at the
  noise floor of this setup). See `scripts/perf.sh` for the A/B method and boundaries.
- Bounded capture: a 1 MiB response produced `stream.bytes=1048880`, `body_prefix` 2048 bytes,
  `timeline` 1 entry, `truncated=true`; worker RSS deltas were dominated by ai-proxy's own body buffering
  and LuaJIT GC (±60 MiB swings on both routes).
