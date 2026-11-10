# Checks on ordinary traffic

The labelled suites answer "is this guardrail right?". These checks answer "where should I look?" on
traffic that carries no labels. Every output is tagged `investigate`. Nothing here is a verdict.

Computed by `evaluator/app/passive.py` over the last `PASSIVE_WINDOW_S` seconds (default 900) of
observations without a trusted runner signature.

| Check | Read from | Signal kind |
|---|---|---|
| AI route with no guardrail, a disabled one, or one that peer routes have | `guardrails_configured`, `configured_plugins` | `coverage:*` |
| Share of requests a guardrail stopped or altered | `exit`, verdicts with `enforced_by` | `high_block_rate` |
| Time in each guardrail (p50/p95/p99) and chain share of gateway time | `trail.gaps[].ms`, `duration_ms` | `slow_guardrail`, `chain_cost` |
| Allowed after about the configured timeout, with no decision | `trail.gaps`, `thresholds.guardrail_timeouts_ms` | `suspected_fail_open` |
| Ran without recording a decision | trail position reached, no verdict | `no_verdict` |
| Flagged but still served | verdict `deny`/`detect` with no enforcement | `detected_not_enforced` |
| Body rewritten across a guardrail, request or response | `gaps[].rewritten`, `response_gaps[].changed` | (in the summary) |
| What the same caller did after a block | per-consumer sequence within `PASSIVE_RETRY_WINDOW_S` | `retry_gets_through`, `retry_storm` |
| Block rate before and after a guardrail config change | `policy_fingerprint` | `guardrail_config_changed` |
| Tokens, cost, model requested vs used, retries, upstream errors | `ai_native`, `attempts`, `response` | `model_differs_from_request`, `upstream_errors` |
| Streaming: time to first chunk, chunk count | `stream` | (in the summary) |

## Endpoints

- `GET /passive/summary?window_s=&route=&include_runs=` everything, with the numbers behind each signal
- `GET /passive/coverage`, `GET /passive/guardrails/{name}`, `GET /passive/signals`
- `GET /passive/agreement` probe trail vs Kong's request-debug trace
- `POST /passive/translate` (runner token) plain-language findings; `GET /passive/findings` the latest
- `GET /chain` the chain drawn in 3D with live numbers
- Prometheus: `go_live_*` gauges (labels: route, guardrail; never consumers). Grafana row "Live traffic".

## Translation

`evaluator/app/translate.py` sends the aggregates and signals, never content, and replaces caller names
with pseudonyms unless `TRANSLATE_INCLUDE_CONSUMERS=true`. Provider is chosen by environment:

| Provider | Needs |
|---|---|
| `anthropic` | `ANTHROPIC_API_KEY` (model `TRANSLATE_MODEL`, default `claude-sonnet-5-5`) |
| `bedrock` | `boto3` in the image, AWS credentials, `BEDROCK_MODEL_ID` (no default: use the id enabled in your account) |
| `stub` | nothing; offline wording taken from the signals (default when nothing is configured) |

A failing provider falls back to the offline translation and reports the error in the result.

## Thresholds (environment)

`PASSIVE_MIN_REQUESTS` 20 · `PASSIVE_HIGH_BLOCK_RATE` 0.30 · `PASSIVE_FAIL_OPEN_RATIO` 0.90 ·
`PASSIVE_CHAIN_SHARE` 0.30 · `PASSIVE_RETRY_WINDOW_S` 120 · `PASSIVE_RETRY_THROUGH_SHARE` 0.50 ·
`PASSIVE_DRIFT_FACTOR` 2.0 · `PASSIVE_DRIFT_MIN_REQUESTS` 5 · `PASSIVE_SLOW_P95_MS` 250

## Limits

- "The same caller" is the Kong consumer, or the client IP when there is none. Behind a shared service
  account every request looks like the same caller and the after-block check means little.
- The summary is recomputed from SQLite on each call (cached 10 s for metrics). Fine for a test bench and
  moderate traffic; a busy production gateway needs sampling or rollups first.
- Kong's http-log queue lives in worker memory: events are lost on a data-plane restart.
- Tried on the local stack only: the drift and after-block checks are covered by unit tests and seeded
  traffic, not by a live config change or real users.
