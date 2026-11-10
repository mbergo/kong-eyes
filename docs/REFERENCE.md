# Kong Guardrail Observer

Measures whether an AI guardrail behind Kong Gateway **overcatches** (blocks/alters legitimate traffic),
**lets violations slip**, or **detects without enforcing** — with evidence you can drill into from
Grafana or Splunk. One Lua plugin inside Kong, one small evaluation service outside it, labeled test
suites, and a 10-minute setup.

```
runner (labels + signed correlation) ──► Kong route: key-auth → guardrail-observer → [input guard] → ai-proxy → [output guard] → observer-tail → http-log
                                                                                                                                      │
evaluator ◄──────────────────────── enriched kong.log.serialize() event (verdicts, phase trace, exit attribution, stream timeline) ────┘
   │  joins labels + gateway evidence + client-received bytes → versioned adjudications → /metrics, OTLP logs, Splunk HEC
   ├──► Alloy → Loki + Prometheus → Grafana dashboard
   └──► Splunk HEC → Splunk dashboard / SPL
```

## Two modes

- **Labelled suites** (below): is this guardrail right? Needs test cases with known answers.
- **Ordinary traffic** (new, `docs/probes.md`, `docs/passive-checks.md`): where should I look? Marker plugins
  around the guardrails give per-guardrail latency, who blocked, rewrites, coverage gaps and suspected
  fail-opens on real requests, as signals to investigate. `make run-chain`, then open the evaluator's
  `/chain` page or the "Live traffic" row in Grafana.

## Status — what was actually verified

| Tier | Status |
|---|---|
| Unit tests (adjudication, exporters) | 20 passing (`make test-unit`) |
| **Kong-tested** on `kong/kong-gateway:3.10.0.19` (free mode; same 3.10 plugin line as this repo's OSS checkout) | all acceptance cases below, phase trace from Kong's own request-debug, exit attribution, streaming, gzip, large bodies, timeout, duplicate ingestion, export outage, evaluator restart |
| Real bundled guardrail (`ai-prompt-guard`, regex policy pg-v1) | 18 labeled cases: **TP 5 · FP 4 · FN 4 · TN 4 · excluded 1 → FPR 4/8, FNR 4/9** (benchmark numbers on an attack-heavy suite, not production rates) |
| Synthetic fixture guardrails (block / detect-only / delayed stream abort) | every seeded outcome classified as intended, incl. 2 streaming enforcement failures and 3 detect-only failures |
| Destination-tested | Grafana (Loki + Prometheus via Alloy, provisioned dashboard, queries return data) · Splunk **HEC-compatible stub** only — protocol/envelope/retry/ack path validated, **no live Splunk connected yet** |
| **Real model** | `/ai/kimi`: real `ai-prompt-guard` in front of ai-proxy → Kimi K3.1 Pro (`api.kimi.com/coding/v1`, Kimi-for-Coding key). 5 labeled cases incl. streaming: TP 1 · FP 1 · FN 1 · TN 2 — guardrail decisions and model answers both observed end to end. Input-stage labels only (model output is not labeled). |
| Your Kong on AWS | **not connected**; `scripts/attach-to-kong.sh` dry-runs against any Admin API and refuses to touch existing loggers |

Everything is pinned (`kong/kong-gateway:3.10.0.19@sha256:a1ce1b…`, python 3.12.7-slim by digest, Grafana 13.2.5, Loki 3.6.19, Alloy v1.21.3, Prometheus v3.15.1). Nothing uses `latest`.

## Quick start (local, ~10 min including image pulls)

```bash
cd guardrail-observer
make up DESTINATION=grafana                 # or: DESTINATION=both STUB=1   (local HEC stub)
make run-suites                             # 5 labeled suites through Kong → evaluator → Grafana/Splunk
make doctor                                 # plugin loaded · scope active · evidence · labels joined · destination · dashboard query
open http://localhost:3000                  # admin/admin → "Guardrail Observer" dashboard
```
Real Splunk: put `SPLUNK_HEC_URL=https://host:8088` and `SPLUNK_HEC_TOKEN=…` (optional `SPLUNK_HEC_INDEX`, `SPLUNK_HEC_ACK=true`) in `.env`, then `make up DESTINATION=both`. The smoke test returns the `smoke_id` and the SPL to find it; with `SPLUNK_SEARCH_URL/TOKEN` set, `scripts/splunk-verify.sh` confirms search visibility (until then the doctor reports *delivery accepted, search verification pending*). Import `observability/splunk/dashboards/guardrail_observer.xml`; SPL library in `observability/splunk/searches.spl`; alert templates (disabled) in `savedsearches.conf`.

Real model: `export KIMI_API_KEY=…` (or `MOONSHOT_API_KEY`) before `make up`, then `make run-kimi`. `setup.sh` picks the base URL from the key prefix (`sk-kimi-*` → `https://api.kimi.com/coding/v1`, otherwise `https://api.moonshot.ai/v1`); override with `KIMI_BASE_URL` / `KIMI_MODEL`. Note: Kimi-for-Coding rejects `temperature` other than 1 and reports it as a 401 "Invalid Authentication" — the evaluator classifies upstream 4xx as `UPSTREAM_OR_GATEWAY_ERROR`, never as a guardrail block.

`setup.sh` is idempotent: secrets in `.env` are generated once and kept; derived files (`kong.generated.yml`) are regenerated; `kong config parse` validates before anything starts.

## What you get per request (the "visibility" part)

Every observed request produces one `kong_observation` event with: trusted runner correlation (HMAC-signed),
bounded request metadata, response status/source, **which plugins executed in which phase with timings**
(Kong's request-debug trace), **which plugin short-circuited** (high confidence from the trace), the full
list of plugin instances configured for the route with config fingerprints, the AI framework's executed
filters, model/provider/tokens, whether a model call was dispatched, per-chunk stream timeline + hashes at
two capture points (before and after the AI/guardrail plugins), request/response encodings, and an explicit
`gaps[]` list. See `docs/schema.md`, `docs/phase-trace.md`, `docs/evidence-table.md`.

Verdicts come from versioned adapters (`docs/adapters.md`): the bundled `ai-prompt-guard` (verified
against 3.10 internals), a `ctx-events` contract for guardrails you control, and a response-header
adapter. Guardrails without a verified adapter show up as `unknown`, never as "allowed".

## Correctness rules the evaluator enforces

- Labels are independent (human, policy-based) and never sent to the guardrail; the guardrail never grades itself.
- Detector matrix (positive = violating): TP/FP/FN/TN; `FPR = FP/(FP+TN)`, `FNR = FN/(FN+TP)`, `N/A` on empty denominators.
- `not_run`, `skipped`, `unknown`, missing verdicts, guardrail errors, auth/rate-limit rejections, timeouts and upstream 5xx are **excluded** from the matrix with a reason — a guardrail that never ran is not a true negative.
- Enforcement is judged from the **client's** bytes (runner), not from the verdict: a detected violation that still reached the client is an `ENFORCEMENT_FAILURE`, with leaked-chunk counts and skew-corrected timing for streams.
- A model refusal is model behaviour (`PASS_BY_OTHER_MEANS`), not guardrail credit. HTTP status is never a verdict.
- Adjudications are versioned; relabeling (`POST /runs/{id}/relabel`) produces a new revision; dashboards select the newest revision per unit; Prometheus exposes recomputed gauges, not counters. Fixture results carry `synthetic=true`.
- Run totals are reconciled against the runner's manifest; unmatched observations are listed after a join timeout.

## Install on an existing Kong (yours on AWS)

1. Build/push the data-plane image with the plugin (`scripts/aws/build-image.sh … --no-fixtures`) or mount the plugin folders with `KONG_LUA_PACKAGE_PATH` — `deploy/aws/README.md`.
2. Append `guardrail-observer,guardrail-observer-tail` to `KONG_PLUGINS` on every data plane (and the control plane for self-managed hybrid; Konnect: `scripts/konnect-upload-schema.sh`). Roll.
3. Run the evaluator next to Kong with `INGEST_TOKEN`, `RUNNER_TOKEN` and your destination variables.
4. `scripts/attach-to-kong.sh --route <route> --environment prod --policy-version <v>` (dry run) → `--apply`. It verifies version/edition/loaded plugins, lists existing loggers and refuses to divert them, and creates three route-scoped instances by `instance_name` (idempotent). deck equivalent: `deploy/konnect/observer.deck.yaml`.
5. Run a suite against the real route (`runner/runner.py --suite …` with `KONG_URL`, `RUNNER_APIKEY`, `KONG_REQUEST_DEBUG_TOKEN`).

Kong only ever learns the evaluator endpoint + ingest token. Destination credentials stay in the evaluator.

## Rollback

`scripts/rollback.sh --route <route> --apply` deletes the three plugin instances (traffic and guardrails untouched). Then remove the two names from `KONG_PLUGINS` and redeploy the previous image — in that order. Locally: `make down` (keep data) / `make clean` (drop volumes).

## Repository layout

```
kong/plugins/guardrail-observer/        handler.lua schema.lua trace.lua adapters.lua runner_auth.lua   (PRIORITY 790)
kong/plugins/guardrail-observer-tail/   post-transform capture point                                   (PRIORITY 5)
kong/plugins/fixture-{input,output}-guard/  synthetic guardrails for evaluator validation (775 / 760)
kong/Dockerfile, kong/*.rockspec, kong/declarative/kong.yml (+ kong.kimi.fragment.yml)
evaluator/            FastAPI + SQLite: ingest, join, adjudicate, /metrics, Splunk HEC + OTLP exporters, tests
runner/               active test runner + labeled suites (cases/*.yaml)
mock-llm/             deterministic OpenAI-compatible model for output-stage fixtures
observability/        alloy/ loki/ prometheus/ grafana/ (provisioning + dashboard JSON + alert templates) splunk/ (stub, SPL, dashboard XML, alerts)
scripts/              setup.sh doctor.sh attach-to-kong.sh rollback.sh konnect-upload-schema.sh splunk-verify.sh perf.sh failure-drills.sh aws/build-image.sh
deploy/               aws/ (README, ECS + EKS snippets) konnect/ (deck snippet)
docs/                 evidence-table.md phase-trace.md adapters.md schema.md RESULTS.md
```

## Known limits

- Ordinary-traffic checks: see the Limits sections of `docs/probes.md` and `docs/passive-checks.md`.

- Kong's http-log queue is worker-local memory: a data-plane restart loses undelivered batches; the evaluator reports them as `runner_without_kong` rather than hiding them.
- Enterprise guardrails (`ai-semantic-prompt-guard`, `ai-azure-content-safety`, `ai-sanitizer`, `ai-custom-guardrail`) have no verified adapter yet → `unknown`. The `ctx-events` contract is the fastest way to make any guardrail you control observable.
- Exit attribution needs the request-debug header (runner does it) or an AI-plugin exiter; passive traffic blocked by a non-AI plugin gets `exit_without_attribution`.
- Gateway telemetry cannot prove a downstream tool/agent action happened; action-level outcomes stay `unknown`.
- Kong OSS 3.10 has no official Docker image; the demo uses the Enterprise image in free mode. On a different Kong version the internal-ctx adapter degrades to `unknown` until re-verified (version gate in `trace.lua`).
