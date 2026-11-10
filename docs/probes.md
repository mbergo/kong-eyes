# Probes: watching a guardrail chain from outside

The guardrails are never modified and do not know they are observed. Tiny marker plugins are placed
around them; the head plugin reads the markers in the log phase.

```
priority  790        775            773        771 / 770          765        760             750      5
          head  ->  guardrail A  ->  probe  ->  guardrail B  ->  probe  ->  guardrail C  ->  probe ... tail
          (A)                        (B)                         (C)                                   (D)
```

## What a probe does

Nothing but leave a mark in the request context (`ngx.ctx.gro_trail`): its priority, a timestamp and,
optionally, a short hash of the request body. On the way back it counts and hashes the response at its
position. A probe that finds no trail (head plugin not on the route) stays silent.

## What the head plugin derives (`trail` in the event, schema 1.1)

| Field | Meaning |
|---|---|
| `request[]` | probes that ran, with time since the head and body hash |
| `gaps[]` | per gap: milliseconds, the third-party plugins that sit in it, `rewritten` when the body hash changed |
| `missing[]` | probes configured on the route that did not run |
| `exit` | when the request was stopped: the gap it stopped in, `candidates`, and `plugin_name` when there is exactly one |
| `response[]`, `response_gaps[]` | the same on the response side: where bytes changed and by how much |

Why it works (Kong 3.10, `docs/phase-trace.md`): plugins run in descending priority in every phase, and
after `kong.response.exit()` in `access` the remaining access handlers are skipped. So the last probe on
the trail is above the plugin that stopped the request and the first missing probe is below it.

`exit.attribution` in the event, in order of preference: `request-debug-trace` (Kong's own trace, test
traffic only), `probe-trail` (one plugin in the gap), `probe-trail+ai-filter-chain` (several plugins in
the gap, narrowed with Kong's AI filter evidence), `ai-filter-chain`, `unavailable`.

## Setting it up for your guardrails

1. **Space the priorities.** Give your guardrails priorities with at least one free number between
   neighbours, all below 790 and above 5, and keep them off 769 and 771 so a probe fits on each side of
   `ai-proxy` (770). Then every block has exactly one candidate.
2. Generate the probes:
   `scripts/gen-probes.sh --guardrails my-pii-guard:780,my-injection-guard:776,ai-proxy:770,my-output-guard:760`
   writes `kong/plugins/gro-probe-<priority>/` and prints the `KONG_PLUGINS` line and the route snippet.
3. Rebuild the image (the Dockerfile copies every `gro-probe-*`), add the names to `KONG_PLUGINS`, roll.
4. On the route: `guardrail-observer` with `guardrail_plugins: [my-pii-guard, ...]` and, if you want the
   fail-open check, `guardrail_timeouts: { my-pii-guard: 800 }`; the probes; `guardrail-observer-tail`;
   a log plugin (`http-log`) pointing at the evaluator.

Open-source Kong fixes one priority per plugin name, which is why each position is its own generated plugin.

## Optional marker header

`trail_header` on the head and `emit_header: true` on a probe also write the trail to a request header as
opaque four-character codes. The head always overwrites whatever arrived under that name. The header
travels upstream, so use it only when the mark must cross a process boundary (a guardrail that is a
separate service, or correlation in downstream logs). The context trail is what covers blocked requests.

## Limits

- Two plugins with adjacent priorities share a gap: latency is not split between them and a block lists
  both as candidates. Spacing removes this for your own plugins; Kong's bundled `ai-prompt-guard` (771)
  next to `ai-proxy` (770) is the one fixed case, resolved at medium confidence from AI filter evidence.
- Plugins that run before the head (authentication, `rate-limiting` at 910) are outside the bracket.
- Kong's AI plugins that edit the parsed prompt (decorator, template) write the raw body only when
  `ai-proxy` runs, so a request hash shows their change in `ai-proxy`'s gap, not their own.
- A probe above `ai-proxy` never sees the end of the response; its hash is finished in the log phase.
- Fractional priorities (a probe at 770.5) were not tested.

## Measured (kong-gateway 3.10.0.19, local stack, 2026-11-09)

- Agreement with Kong's request-debug trace on blocked requests that carry both: 19 compared, 0 disagreements
  (4 exact, 15 where the trace's plugin is among the trail's candidates). `GET /passive/agreement`.
- Overhead of three probes, A/B over 400 interleaved requests (`scripts/perf-probes.sh`): p50 +0.03 ms,
  p95 +0.17 ms, mean +0.07 ms, on small bodies with hashing on.
