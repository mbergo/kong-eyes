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

## The dashboard

Open `http://localhost:8800/dashboard`. It is one page, served by the collector itself, written for people who have
never opened Kong: a few sentences saying what happened, a picture of where the requests went, one panel per
guardrail with what each number means, charts over time, the patterns worth a look, and the requests one by one.
It needs no Grafana, Loki or Prometheus.

**The dashboard has no login.** It shows callers, request ids and, when prompt capture is on, the start of each prompt.
The collector's port is therefore bound to this machine only (`EVALUATOR_BIND=127.0.0.1`). Do not put it on a network
others can reach without something in front of it (a VPN, a private network, or a proxy that asks for a password).

## `koe`: connect to any Kong without installing anything

`koe` is the Kong Eyes command line (and a Brazilian way of saying hello).

For a demo, `bin/koe demo traffic --kong-url http://localhost:8000 --apikey KEY` sends about 60 requests a second with a mix
that changes every few seconds (calm, attack burst, disguised attacks, slow backend, recovery). Open the chain with
`/chain?window_s=60&poll_s=2`, or the demo console, to watch it follow.

```bash
bin/koe connect --admin-url http://kong-admin:8001 --route my-ai-route \
    --ingest-url https://<eyes-host>/ingest/kong --ingest-token ... --timeout-ms 400
bin/koe status
bin/koe disconnect --route my-ai-route
```

`connect` adds three plugins Kong already ships (pre-function, post-function, http-log) to the route through the
Admin API. No image rebuild, no custom plugin. It works on DB-backed and DB-less Kong, asks before changing
anything, and `--dry-run` only reports. For a route with **one** guardrail it gives, per request: served or
stopped, who stopped it, the time the guardrail took, and whether it waited for its timeout and then let the
request through.

| | Bundled plugins (`koe connect`) | Probe plugins (`attach-to-kong.sh`) |
|---|---|---|
| Install on the gateway | Nothing | Plugin files in the image |
| Who stopped a request | By elimination: auth passed and the model plugin never ran | By position in the trail |
| Time in the guardrail | Time of the whole access chain; exact when the guardrail is the one slow plugin | Exact, per guardrail |
| More than one guardrail | No, they share one bracket | Yes |
| Needs | `untrusted_lua` not `off` (Kong's default is fine) | Kong 3.10 line |

## Three scripts

| You want to | Run |
|---|---|
| Stand up the dashboard on AWS, on HTTPS | `scripts/aws-up.sh NAME` |
| Put the probes on a route of your Kong | `scripts/attach-to-kong.sh --route R --guardrails a:780,b:776` |
| Send prompts at a Kong route as load | `scripts/kong-load.py URL -H 'apikey: KEY'` |

### 1. `scripts/aws-up.sh NAME`: the dashboard on a t3.small

```bash
scripts/aws-up.sh eyes-demo                     # uses your AWS CLI credentials and region
scripts/aws-up.sh eyes-demo --domain eyes.example.com
scripts/aws-up.sh eyes-demo --destroy           # removes the instance, security group and key pair
```

Creates a key pair, a security group (SSH from your IP only, 80/443 open) and one Ubuntu instance named
`NAME`, ships this repo to it and runs `deploy/install.sh --https`. Caddy gets the certificate on its own
(Let's Encrypt, ZeroSSL as fallback). Without `--domain` the address is `https://<ip-with-dashes>.sslip.io`.
The host runs a demo Kong with synthetic guardrails and traffic so the dashboard has something to show.

| Path on the host | What |
|---|---|
| `/` | Grafana. Dashboard "Guardrail chain - live traffic", with the 3D chain embedded and a legend for every panel |
| `/eyes/*` | Read-only chain view and summaries, served only to a browser logged in to Grafana |
| `/ingest/kong` | Where your own Kong posts its events (needs the ingest token) |
| `/kong/*` | The demo Kong proxy (key-auth), a target for the load script |

### 2. `scripts/attach-to-kong.sh`: the probes on your Kong

```bash
scripts/gen-probes.sh --guardrails my-input-guard:780,my-pii-guard:776,ai-proxy:770,my-output-guard:760
# build the image (kong/Dockerfile), add the printed names to KONG_PLUGINS, roll your data planes, then:
KONG_ADMIN_URL=https://kong-admin:8001 EVALUATOR_INGEST_URL=https://<eyes-host>/ingest/kong \
INGEST_TOKEN=... RUNNER_SECRET=... \
scripts/attach-to-kong.sh --route my-ai-route \
  --guardrails my-input-guard:780,my-pii-guard:776,ai-proxy:770,my-output-guard:760 \
  --timeouts my-input-guard:400            # dry run; add --apply
```

It checks the gateway version and that every plugin is loaded, shows the payloads, never touches your
guardrails or existing loggers, and is idempotent. `scripts/rollback.sh --route my-ai-route --apply` removes it.

You do not have to list every plugin. The head plugin reads the route's full plugin list from Kong, so any
plugin sitting between two probes is **found by its position and shown under its own name** (its
`instance_name` if you gave it one), with the same latency and block attribution. `--guardrails` only tells
the script where to put probes and which plugins to treat as guardrails in the coverage checks.

### 3. `scripts/kong-load.py URL`: prompts as load

```bash
scripts/kong-load.py https://kong.example.com/ai/chat -H 'apikey: KEY' --minutes 10 --rps 3
scripts/kong-load.py https://<eyes-host>/kong/ai/chain -H 'apikey: KEY' --demo      # against the demo Kong
```

Random prompts every run: benign ones are built from parts (task x topic x style), and well-known
injection, PII and secret-shaped test strings are wrapped in a random benign request. Traffic moves through
phases (normal, attack wave, quiet) unless `--steady`. `--mix`, `--stream` and `--prompts FILE` change the
blend. It prints status codes per category and latency; the dashboard says which plugin answered.

## Trying it with your own guardrail names

```bash
scripts/gen-demo-guards.sh onyx straiker      # any names; stand-ins, not the real products
make up DESTINATION=grafana                   # rebuild and reload Kong
scripts/mock-flow.py --path /ai/named
```

This puts synthetic stand-in guardrails with the names you give on the route `/ai/named`, with probes between
them, so the dashboard and the chain view show your names before the real plugins are wired in. Their
behaviour is scripted (the first overcatches a decoy marker, the second sometimes times out and fails open), so
what the panels show for those names says nothing about any real product. The generated folders are kept out of
git. `scripts/gen-demo-guards.sh --remove` takes them away.

### The demo console

Set `DEMO_CONSOLE=true` in `.env`, restart the evaluator, and open `http://localhost:8800/demo`. It is a separate
page for demos only: sliders for each stand-in (how much it lets slip, how much it overcatches, whether it fails
open and its timeout), start/stop and mix of the mock traffic, an attack wave on demand, the prompt-capture
switch and a button to refresh the findings, with the live chain beside it. Changes are applied through Kong's
Admin API to the stand-ins on `/ai/named` only, and are gone when Kong restarts. It has no login of its own: keep
it on localhost, or use the HTTPS install (`deploy/install.sh --https --demo-guards "onyx straiker"`), which serves it at
`/eyes/demo` behind the Grafana login. Never enable it on an evaluator that can reach a real gateway's Admin API.

In the chain view every guardrail has its own colour, used for its outline, its label and its table row.
Colour is never a fill.

## Requests and prompts

The "Requests and prompts" dashboard is the request-by-request view, and the home page on an installed host: one
line per request with its status, whether it was served, stopped (and by which plugin) or made to wait at a
guardrail, the time each plugin held it, and the start of the prompt. It is built from the evaluator's events
in Loki; there is no separate tracing backend.

## Seeing the prompts

The dashboard has a "Requests, one by one" row: status, served or stopped by which plugin, gateway time,
and the start of the prompt. Prompts appear only when two switches are on, and both are off by default:

1. the route's observer captures bodies: `capture_body_mode: bounded`
2. the evaluator exports an excerpt: `EXPORT_PROMPT_CHARS=240`

With the defaults (`hash`, `0`) no content leaves Kong. The demo install turns both on because its traffic
is synthetic. Think before doing that on a route with real users.

## Run it locally

```bash
make up DESTINATION=grafana     # build, validate, start, smoke-test
make run-chain                  # ordinary traffic through the probed chain, then print the signals
scripts/mock-flow.py --minutes 30
```

Grafana is on `http://localhost:3000`, the chain view on `http://localhost:8800/chain`. On a remote host
you already have, `scripts/deploy-remote.sh user@host -i key.pem -- --https` does the same as `aws-up.sh`
without creating anything in AWS.

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
- `scripts/aws-up.sh` (creating the instance). `scripts/deploy-remote.sh` and `deploy/install.sh --https --demo-guards` have run
  end to end on a 2 vCPU / 2 GB Ubuntu 24.04 EC2 host, including a browser-style login to the console.
- Long runs. The first 12-hour run filled the store and hung the evaluator; an index, retention (`RETENTION_HOURS`) and
  a traffic auto-stop were added after that. Nothing has run longer than that since.
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
docs/                                   probes, passive checks, schema, adapters, results, request-flow-3d.html
```

[docs/request-flow-3d.html](docs/request-flow-3d.html) is a standalone 3D walk through a request crossing Kong as an AI
gateway, component by component, including where a plugin fits. Open it in a browser.

The second mode, grading a guardrail against labelled test suites, plus Splunk export, rollback and
the full list of known limits, is documented in [docs/REFERENCE.md](docs/REFERENCE.md).
