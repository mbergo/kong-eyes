# Deploying to Kong on AWS (ECS / EKS / EC2, self-managed or Konnect data planes)

Nothing here was run against your AWS account; these are the exact steps the local stack already
proves, mapped onto the AWS packaging you use. Two things change: **where the image is built/pushed**
and **how the three plugin instances are created**.

## 1. Build and push the data-plane image (10 min, once)

```bash
# from guardrail-observer/
export AWS_REGION=us-east-1 ACCOUNT=<account-id> REPO=kong-guardrail-observer
aws ecr create-repository --repository-name $REPO --image-scanning-configuration scanOnPush=true || true
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com
scripts/aws/build-image.sh $ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO:3.10.0.19-go0.1.0 \
  --base kong/kong-gateway:3.10.0.19@sha256:a1ce1bc060c1379a5da26db50a2cd1e43db15efbd79b9dff563f18c6e52df282 --no-fixtures
```
`--no-fixtures` leaves the synthetic guardrails out of production images. Use your own hardened
base with `--base` if you have one; the plugin only needs `/usr/local/share/lua/5.1/kong/plugins/`.

If you cannot change the image (e.g. a shared platform image), mount the four `plugins/*` folders
into the container and set `KONG_LUA_PACKAGE_PATH=/opt/kong-plugins/?.lua;;` instead
(`deploy/aws/ecs-task-snippet.json` shows both variants).

## 2. Activate the plugins on every data plane (declare, roll, verify)

Add to the Kong container environment, **preserving what is already there**:
```
KONG_PLUGINS=bundled,guardrail-observer,guardrail-observer-tail     # append to your existing list
KONG_REQUEST_DEBUG=on                                                # default on; keep it
KONG_REQUEST_DEBUG_TOKEN=<secret from Secrets Manager>               # lets the runner request a phase trace
```
Roll the ECS service / EKS deployment. Verify on one node: `GET :8001/` (or the status/debug port)
→ `plugins.available_on_server` contains `guardrail-observer`. `scripts/attach-to-kong.sh` checks this.

Hybrid control plane: the **control plane** also needs the plugin schema to accept the configuration:
- self-managed CP: install the same files on the CP image and add the names to its `KONG_PLUGINS`;
- Konnect: `scripts/konnect-upload-schema.sh` (uploads `schema.lua` only), then deck/UI.

## 3. Create the three plugin instances on ONE route

- Admin API (self-managed): `scripts/attach-to-kong.sh --route <name> --environment prod --policy-version <v> --apply`
- Konnect / deck: `deploy/konnect/observer.deck.yaml` → `deck gateway sync`
- Terraform (kong provider): mirror the three resources from the deck file.

Secrets: `runner_shared_secret` and the http-log `http_endpoint` are vault-referenceable → use
`{vault://aws/guardrail-observer/runner-secret}` with Kong's AWS Secrets Manager vault instead of
literals. Kong needs **only** the evaluator endpoint + ingest token; Splunk/Grafana credentials never
touch Kong.

## 4. Run the evaluator next to Kong

The evaluator is one container (FastAPI + SQLite volume). Run it as an ECS service / Deployment in
the same VPC with `INGEST_TOKEN`, `RUNNER_TOKEN`, and the destination variables from `.env.example`
(`SPLUNK_HEC_URL/TOKEN/INDEX`, or `OTLP_LOGS_ENDPOINT` → an Alloy sidecar/DaemonSet → Grafana Cloud).
Expose `/metrics` to your Prometheus/Alloy scrape. Put it behind an internal ALB with TLS; Kong's
http-log sends `Authorization: Basic kong:<INGEST_TOKEN>`.

## 5. Run a labeled suite against the real route

```bash
KONG_URL=https://<your proxy> EVALUATOR_URL=https://<evaluator> RUNNER_TOKEN=... RUNNER_SECRET=... \
RUNNER_APIKEY=<a consumer key allowed on that route> KONG_REQUEST_DEBUG_TOKEN=... \
python3 runner/runner.py --suite runner/cases/prompt-guard.yaml --settle 10
```
Adapt `path`, `route`, `guardrail` and `policy_version` in the suite file to your route. Only
`guardrail: ai-prompt-guard` (bundled) and `ctx-events`/`response-header` guardrails have verified
adapters on 3.10; enterprise guardrails (`ai-semantic-prompt-guard`, `ai-azure-content-safety`,
`ai-sanitizer`) surface as `unknown` until an adapter is verified against them (docs/adapters.md).

## Rollback

`scripts/rollback.sh --route <name> --apply` removes the three instances (traffic unaffected;
guardrails untouched). Full removal: drop the two names from `KONG_PLUGINS`, redeploy the previous
image. Order matters: delete instances **before** removing the names from `KONG_PLUGINS`, otherwise
Kong refuses to start with configuration for an unknown plugin.
