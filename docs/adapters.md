# Guardrail adapters (versioned contracts)

Every verdict in a `kong_observation` is produced by an adapter and carries `adapter`, `provenance`,
`supported`, `reason`, and raw `evidence`. The evaluator treats `supported=false`, `unknown`, `missing`,
`not_run`, `skipped` as **inconclusive** — never as a true negative.

| Adapter | Guardrail(s) | Stage | How the verdict is obtained | Verified on |
|---|---|---|---|---|
| `ai-prompt-guard@1` | bundled `ai-prompt-guard` | input | internal ctx: `ai_executed_filters["guard-prompt"]`, `ai_namespaced_ctx["guard-prompt"].guarded`; deny = executed ∧ ¬guarded ∧ exit 400 attributed to the plugin (request-debug trace, high) or no later AI filter (medium); 500 = `error` | 3.10.0 source, 3.10.0.19 runtime |
| `ctx-events@1` | any plugin that appends to `ngx.ctx.guardrail_events` (fixtures, your own guardrails) | input/output | explicit records written by the guardrail itself; no inference | contract defined here |
| `response-header@1` | vendors that stamp `X-Guardrail-Verdict` (configurable) | from header | `allow|deny|detect|error[;stage=…;action=…]` | contract defined here |
| *(none)* | `ai-semantic-prompt-guard`, `ai-azure-content-safety`, `ai-sanitizer`, `ai-custom-guardrail` | — | reported as `verdict=unknown, supported=false` when configured on the route | not verified (license-gated / not in 3.10 OSS) |

## ctx-events contract (recommended for guardrails you control)

Append one table per decision:

```lua
local evs = ngx.ctx.guardrail_events or {}
evs[#evs + 1] = {
  guardrail  = "my-guard",            -- plugin name
  stage      = "input" | "output",
  verdict    = "allow" | "deny" | "detect" | "error" | "skipped",
  mode       = "block" | "detect" | "disabled",
  action     = "block" | "redact" | "transform" | "abort_stream" | "none",
  enforced_by = "my-guard",           -- component that produced the client-visible effect (nil if none)
  status     = 403,                   -- when the guardrail produced the response
  reason     = "pattern X matched",
  evidence   = { body_sha256 = ..., matched_rule = ..., detected_chunk = 3, leaked_chunks = 0 },  -- bounded, no content
}
ngx.ctx.guardrail_events = evs
```
Rules: write the event **before** calling `kong.response.exit`/modifying the body; include pre-enforcement
evidence (hash/size/rule/chunk index) so the decision can be judged without the replacement body; never
include prompt or response text; one event per stage per decision (the evaluator takes the latest `seq`
for a (guardrail, stage)).

## Adding an adapter for an enterprise/vendor guardrail

1. Find where the plugin exposes its decision: a `kong.log.set_serialize_value` key (preferred — read it
   from the exported event in the evaluator, not in Lua), a response header, or internal ctx.
2. If it is a serialized-log field, add normalization in `evaluator/app/ingest.py` (`extract_observer`) and
   a `vendor-log@1` record; if it is a header, configure `verdict_header`/`verdict_header_guardrail`;
   if it is internal ctx, add a function in `kong/plugins/guardrail-observer/adapters.lua` **gated by the
   exact Kong version it was verified on** and set `supported=false` elsewhere.
3. Prove it with the fixture pattern: seed each outcome, run the suite, compare to labels.
4. Record the file/line you verified in this table.
