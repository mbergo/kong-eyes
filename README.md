# kong-eyes

**See what your AI guardrails are actually doing inside Kong, without touching them.**

You run two or three guardrail plugins in front of an LLM. Are they blocking too much? Letting
things through? Timing out and failing open? Even running on every AI route? kong-eyes puts tiny
marker plugins around each guardrail, collects what they see, and turns it into signals you can
investigate, a live dashboard, and a plain-language summary written by Claude.

It reports **signals to investigate, never verdicts**. A high block rate is a reason to look, not
proof that a guardrail is wrong.

```
client ─► Kong route
            │
            ├─ A  guardrail-observer        (790)  starts the trail
            ├─    your input guardrail
            ├─ B  gro-probe-<n>                    marks: reached here, at t, body hash
            ├─    your second guardrail
            ├─ C  gro-probe-<n>
            ├─    ai-proxy ─► model
            ├─    your output guardrail
            └─ D  guardrail-observer-tail   (5)    closes the trail, ships one event
                                                        │
        evaluator (FastAPI + SQLite) ◄──────────────────┘
            ├─ passive checks ─► /passive/* · Prometheus gauges ─► Grafana
            ├─ Claude translation of the aggregates ─► findings
            └─ /chain  live 3D view of the guardrail chain
```

## What it tells you

| Signal | How it is derived |
|---|---|
| Who blocked a request | The trail stops between two probes; the guardrail in that gap is the candidate |
| Block rate per guardrail | Blocks attributed to each gap, per route |
| Latency per guardrail, and the chain's share of the total | Time between neighbouring probes |
| Suspected fail-open | Request allowed after roughly the guardrail's configured timeout |
| Rewrites | Body hash or size changes across a gap |
| Coverage gaps | AI route where a configured guardrail never ran, or with no guardrail at all |
| Detected but not enforced | A guardrail flagged the request and it still reached the client |
| Retry after a block | Same caller tries again shortly after, and whether it got through |
| Drift | Block rate or latency before and after a config change |
| Traffic facts | Tokens, model, upstream errors, streaming time to first chunk |

Your guardrails are not modified. The probes only read and annotate the request context.

## Quick start

On a fresh Linux host (Docker is installed for you):

```bash
git clone git@github.com:mbergo/kong-eyes.git && cd kong-eyes
deploy/install.sh --mock-minutes 30
```

Or from your laptop to a remote host over SSH:

```bash
scripts/deploy-remote.sh ubuntu@<host> -i ~/key.pem -- --mock-minutes 30
```

Already have Docker and just want it locally:

```bash
make up DESTINATION=grafana     # build, validate, start, smoke-test
make run-chain                  # ordinary traffic through the probed chain, then print the signals
```

Then open:

| | |
|---|---|
| Grafana | `http://localhost:3000` → "Guardrail chain - live traffic" |
| Chain view | `http://localhost:8800/chain` |
| Signals (JSON) | `http://localhost:8800/passive/signals` |

`deploy/install.sh` binds every port to localhost by default; it prints the SSH tunnel command.
Pass `--bind 0.0.0.0` only on a host you have firewalled.

## Using it with your own guardrails

1. Generate one probe per gap between your guardrails:

   ```bash
   scripts/gen-probes.sh --guardrails my-input-guard:780,my-pii-guard:776,my-output-guard:760
   ```

   It writes `kong/plugins/gro-probe-<priority>/` and prints the `KONG_PLUGINS` line and the route
   snippet. Leave a free priority number between neighbouring guardrails so a probe fits between
   them, and keep clear of 769 and 771 around `ai-proxy` (770).
2. Build the data-plane image (`kong/Dockerfile`, or `scripts/aws/build-image.sh --no-fixtures`).
3. Attach to a route: `scripts/attach-to-kong.sh --route <route>` is a dry run; add `--apply`.
4. Run the evaluator next to Kong. Kong only learns the evaluator's ingest endpoint and token.

Details: [docs/probes.md](docs/probes.md), [docs/passive-checks.md](docs/passive-checks.md).

## Claude translation

`POST /passive/translate` sends **aggregates only** (no prompts, no responses, callers
pseudonymised) and stores short findings, each tagged *investigate*.

```bash
# .env
TRANSLATE_PROVIDER=anthropic      # or bedrock, or stub (default, offline)
ANTHROPIC_API_KEY=...
```

With `bedrock`, set `BEDROCK_MODEL_ID` and `AWS_REGION`; the data stays in your AWS account.

## Where it runs

| Kong deployment | Works? |
|---|---|
| Self-hosted Kong (OSS or Enterprise), DB-less or hybrid | Yes. Tested on Kong Gateway 3.10 |
| Konnect with your own data plane (hybrid) | Yes in principle: upload the schemas (`scripts/konnect-upload-schema.sh`) and run this image as the data plane. Not yet run end to end |
| Konnect Dedicated Cloud Gateway | Needs each plugin as a single handler + schema; the head plugin is not packaged that way yet |
| Konnect Serverless | No. Custom plugins are not supported there |

## What has been verified, and what has not

Verified on a real Kong 3.10 gateway with synthetic guardrails and a mock model:

- Probe-trail attribution agrees with Kong's own request-debug trace on every blocked request compared (19 of 19).
- Three probes add about 0.03 ms at p50 and 0.17 ms at p95.
- Seeded fail-open, coverage gap, output rewrite and retry-after-block all surface as signals.
- 39 unit tests pass (`make test-unit`).

Not verified yet:

- A live Claude call (only the offline stub has run) and the Bedrock path.
- `deploy/install.sh` and `scripts/deploy-remote.sh` on a real remote host.
- Real guardrails, production traffic volumes, and any Konnect-hosted data plane.
- Kong versions other than 3.10. The internal adapters are version-gated and degrade to `unknown`.

## Layout

```
kong/plugins/guardrail-observer/        head plugin: trail, attribution, event        (priority 790)
kong/plugins/guardrail-observer-tail/   tail plugin: closes the trail                  (priority 5)
kong/plugins/_probe-template/           template for the generated middle probes
kong/plugins/fixture-*-guard/           synthetic guardrails for tests only
evaluator/                              ingest, passive checks, translation, metrics, /chain
runner/                                 test runner and suites
observability/                          Grafana dashboards, Loki, Prometheus, Alloy, Splunk
scripts/                                setup, probe generator, attach, rollback, deploy, mock traffic
deploy/                                 install.sh, AWS and Konnect snippets
docs/                                   probes, passive checks, schema, adapters, results
```

The second mode, grading a guardrail against labelled test suites, plus Splunk export, rollback and
the full list of known limits, is documented in [docs/REFERENCE.md](docs/REFERENCE.md).
