#!/usr/bin/env bash
# One-command install on a fresh Linux host (written for Ubuntu 24.04, 2 vCPU / 2 GB).
#
#   deploy/install.sh [--https [--domain NAME]] [--bind 127.0.0.1|0.0.0.0] [--demo-guards "NAME NAME"]
#                     [--destination grafana|splunk|both] [--swap-gb N] [--mock-minutes N]
#                     [--no-docker-install]
#
# What it does, in order:
#   1. installs Docker Engine + compose plugin if missing (get.docker.com)
#   2. adds a swap file when the host has < 3.5 GB RAM and no swap
#   3. writes docker-compose.override.yml: published ports bound to --bind (default 127.0.0.1)
#      and a Grafana data volume
#   4. generates a random Grafana admin password in .env if none is set
#   5. --https: adds Caddy on 80/443 with an automatic certificate, puts Grafana behind it and
#      embeds the 3D chain view in the dashboard. Without --domain it uses <public-ip>.sslip.io
#   6. runs scripts/setup.sh (secrets, config validation, build, start, smoke, doctor)
#   7. optionally starts synthetic traffic (--mock-minutes)
#   --demo-guards "a b": also generates stand-in guardrails with those names on /ai/named, turns on the demo
#      console (/demo, or https://<domain>/eyes/demo behind the Grafana login) and starts its traffic
#
# Idempotent: re-run it after pulling a new version. Nothing here touches your own Kong;
# to attach the probes to an existing gateway use scripts/attach-to-kong.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

BIND="127.0.0.1"; DEST="grafana"; SWAP_GB=2; MOCK_MIN=0; INSTALL_DOCKER=1; HTTPS=0; DOMAIN=""; GUARDS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bind) BIND="$2"; shift 2;;
    --destination) DEST="$2"; shift 2;;
    --swap-gb) SWAP_GB="$2"; shift 2;;
    --mock-minutes) MOCK_MIN="$2"; shift 2;;
    --https) HTTPS=1; shift;;
    --demo-guards) GUARDS="$2"; shift 2;;
    --domain) DOMAIN="$2"; HTTPS=1; shift 2;;
    --no-docker-install) INSTALL_DOCKER=0; shift;;
    -h|--help) sed -n '2,23p' "$0"; exit 0;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac
done
say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
SUDO=""; [[ $EUID -eq 0 ]] || SUDO="sudo"
getenv() { grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2- || true; }
setenv() { if grep -qE "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi; }

# ---------------------------------------------------------------- 1. docker
if ! command -v docker >/dev/null 2>&1; then
  [[ $INSTALL_DOCKER -eq 1 ]] || { echo "docker missing and --no-docker-install given" >&2; exit 1; }
  say "Installing Docker Engine"
  curl -fsSL https://get.docker.com | $SUDO sh >/tmp/gro-docker-install.log 2>&1 \
    || { tail -20 /tmp/gro-docker-install.log; exit 1; }
fi
# run docker as this user; fall back to `sg docker` when the group was only just added
DRUN() { "$@"; }
if ! docker info >/dev/null 2>&1; then
  $SUDO usermod -aG docker "$(id -un)" 2>/dev/null || true
  if sg docker -c "docker info" >/dev/null 2>&1; then
    DRUN() { sg docker -c "$(printf '%q ' "$@")"; }
  else
    echo "cannot talk to the docker daemon as $(id -un)" >&2; exit 1
  fi
fi
DRUN docker compose version >/dev/null 2>&1 || { echo "docker compose v2 plugin required" >&2; exit 1; }

# ------------------------------------------------------------------ 2. swap
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
SWAP_MB=$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo)
if [[ $SWAP_GB -gt 0 && $MEM_MB -lt 3500 && $SWAP_MB -lt 512 ]]; then
  say "Host has ${MEM_MB} MB RAM and no swap: adding a ${SWAP_GB} GB swap file"
  $SUDO fallocate -l "${SWAP_GB}G" /swapfile && $SUDO chmod 600 /swapfile
  $SUDO mkswap /swapfile >/dev/null && $SUDO swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' | $SUDO tee -a /etc/fstab >/dev/null
fi

# ------------------------------------------------------------- 3-5. config
mkdir -p .build; [[ -e .build/empty-ca.crt ]] || : > .build/empty-ca.crt
touch .env; chmod 600 .env
if [[ -z "$(getenv GRAFANA_ADMIN_PASSWORD)" ]]; then
  setenv GRAFANA_ADMIN_PASSWORD "$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | cut -c1-20)"
  say "Generated a Grafana admin password (stored in .env)"
fi
[[ -n "$(getenv TRANSLATE_EVERY_S)" ]] || setenv TRANSLATE_EVERY_S 300
[[ -n "$(getenv RETENTION_HOURS)" ]] || setenv RETENTION_HOURS 6        # small demo host: keep the store small
# the bundled demo routes carry synthetic prompts only, so the dashboard may list them
[[ -n "$(getenv EXPORT_PROMPT_CHARS)" ]] || setenv EXPORT_PROMPT_CHARS 240

GF_EXTRA=""; CADDY=""; CADDY_VOL=""; EV_EXTRA=""
if [[ -n "$GUARDS" ]]; then
  say "Generating stand-in guardrails: $GUARDS"
  # shellcheck disable=SC2086
  scripts/gen-demo-guards.sh $GUARDS | head -1
  setenv DEMO_CONSOLE true
fi
if [[ $HTTPS -eq 1 ]]; then
  [[ "$DEST" != "splunk" ]] || { echo "--https serves Grafana: use --destination grafana or both" >&2; exit 2; }
  if [[ -z "$DOMAIN" ]]; then
    IP="$(curl -fsS --max-time 5 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]')"
    [[ "$IP" =~ ^[0-9.]+$ ]] || { echo "could not find this host's public IP; pass --domain" >&2; exit 1; }
    DOMAIN="${IP//./-}.sslip.io"
  fi
  setenv EYES_DOMAIN "$DOMAIN"
  [[ -n "$(getenv CADDY_IMAGE)" ]] || setenv CADDY_IMAGE "caddy:2-alpine"
  BIND="127.0.0.1"
  GF_EXTRA="    environment:
      GF_SERVER_ROOT_URL: https://${DOMAIN}/
      GF_PANELS_DISABLE_SANITIZE_HTML: \"true\"   # lets the dashboard embed the chain view"
  CADDY="  caddy:
    image: \${CADDY_IMAGE}
    profiles: [grafana]
    restart: unless-stopped
    environment:
      EYES_DOMAIN: \${EYES_DOMAIN}
    ports: [\"80:80\", \"443:443\"]
    volumes:
      - ./deploy/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
    depends_on: [grafana, evaluator, kong]"
  CADDY_VOL="  caddy-data: {}"
  EV_EXTRA="    environment:
      DEMO_GRAFANA_URL: https://${DOMAIN}"
  say "HTTPS on https://${DOMAIN} (certificate issued automatically by Caddy)"
  python3 observability/grafana/build_live_dashboard.py --embed-chain '/eyes/chain?theme=dark'
fi

say "Writing docker-compose.override.yml (ports bound to ${BIND})"
cat > docker-compose.override.yml <<YAML
# Generated by deploy/install.sh. Delete this file to go back to the plain compose defaults.
services:
  kong:
    ports: !override
      - "${BIND}:\${KONG_PROXY_PORT:-8000}:8000"
      - "127.0.0.1:\${KONG_ADMIN_PORT:-8001}:8001"
      - "127.0.0.1:\${KONG_STATUS_PORT:-8100}:8100"
  evaluator:
${EV_EXTRA}
    ports: !override
      - "${BIND}:\${EVALUATOR_PORT:-8800}:8000"
  alloy:
    ports: !override
      - "127.0.0.1:\${ALLOY_PORT:-12345}:12345"
      - "127.0.0.1:\${OTLP_HTTP_PORT:-4318}:4318"
  loki:
    ports: !override
      - "127.0.0.1:\${LOKI_PORT:-3100}:3100"
  prometheus:
    ports: !override
      - "127.0.0.1:\${PROMETHEUS_PORT:-9090}:9090"
  grafana:
${GF_EXTRA}
    ports: !override
      - "${BIND}:\${GRAFANA_PORT:-3000}:3000"
    volumes:
      - grafana-data:/var/lib/grafana
${CADDY}
volumes:
  grafana-data: {}
${CADDY_VOL}
YAML

# ----------------------------------------------------------------- 6. stack
say "Running scripts/setup.sh --destination ${DEST}"
DRUN scripts/setup.sh --destination "$DEST"

# ------------------------------------------------------------------ 7. mock
if [[ $MOCK_MIN -gt 0 ]]; then
  say "Starting synthetic traffic for ${MOCK_MIN} min (log: /tmp/gro-mock-flow.log)"
  pkill -f '[m]ock-flow.py' 2>/dev/null || true
  (setsid nohup python3 scripts/mock-flow.py --minutes "$MOCK_MIN" >/tmp/gro-mock-flow.log 2>&1 &)
fi

if [[ -n "$GUARDS" ]]; then
  say "Starting the demo console's traffic"
  set -a; . ./.env; set +a
  for _ in $(seq 1 20); do
    curl -fsS -m 10 -X POST -H "Content-Type: application/json" -d '{"running":true,"rps":4}' \
      "http://localhost:${EVALUATOR_PORT:-8800}/demo/traffic" >/dev/null 2>&1 && break; sleep 3
  done
fi

set -a; . ./.env; set +a
echo
say "Installed"
if [[ $HTTPS -eq 1 ]]; then
  echo "   Dashboard   https://${DOMAIN}/d/guardrail-live     user ${GRAFANA_ADMIN_USER:-admin}"
  echo "   Password    grep GRAFANA_ADMIN_PASSWORD $(pwd)/.env"
  [[ -z "$GUARDS" ]] || echo "   Console     https://${DOMAIN}/eyes/demo            log in to Grafana first"
  echo "   Kong (demo) https://${DOMAIN}/kong/ai/chain          target for scripts/kong-load.py --demo"
  echo "   Ingest      https://${DOMAIN}/ingest/kong            EVALUATOR_INGEST_URL for scripts/attach-to-kong.sh"
  echo "   The first page load can take up to a minute while the certificate is issued."
else
  HOST_HINT="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [[ "$BIND" == "127.0.0.1" ]]; then
    echo "   Ports are bound to localhost. From your machine:"
    echo "     ssh -N -L ${GRAFANA_PORT:-3000}:localhost:${GRAFANA_PORT:-3000} -L ${EVALUATOR_PORT:-8800}:localhost:${EVALUATOR_PORT:-8800} <user>@<this-host>"
    HOST_HINT="localhost"
  fi
  echo "   Grafana     http://${HOST_HINT}:${GRAFANA_PORT:-3000}   user ${GRAFANA_ADMIN_USER:-admin}, password: grep GRAFANA_ADMIN_PASSWORD .env"
  echo "   Chain view  http://${HOST_HINT}:${EVALUATOR_PORT:-8800}/chain"
  echo "   Kong proxy  http://${HOST_HINT}:${KONG_PROXY_PORT:-8000}"
fi
