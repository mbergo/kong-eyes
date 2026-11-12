#!/usr/bin/env bash
# One-command install on a fresh Linux host (written for Ubuntu 24.04, 2 vCPU / 2 GB).
#
#   deploy/install.sh [--https [--domain NAME[,NAME...]]] [--user NAME] [--password-file FILE]
#                     [--demo-guards "NAME NAME"] [--destination none|grafana|splunk|both]
#                     [--bind 127.0.0.1|0.0.0.0] [--swap-gb N] [--no-docker-install]
#
# What it does, in order:
#   1. installs Docker Engine + compose plugin if missing (get.docker.com)
#   2. adds a swap file when the host has < 3.5 GB RAM and no swap
#   3. writes docker-compose.override.yml: published ports bound to --bind (default 127.0.0.1)
#   4. --https: adds Caddy on 80/443 with an automatic certificate and ONE user and password in front of
#      everything (the dashboard is the home page). Without --domain it uses <public-ip>.sslip.io.
#      The password comes from --password-file (read once, then deleted) or is generated and printed once.
#      Only its hash is kept, in deploy/auth.caddy.
#   5. --demo-guards "a b": generates stand-in guardrails with those names on /ai/named, turns on the demo
#      console (/demo) and starts its traffic
#   6. runs scripts/setup.sh (secrets, config validation, build, start)
#
# The default destination is "none": the collector's own dashboard needs no Grafana, Loki or Prometheus.
# Idempotent: re-run it after pulling a new version. Nothing here touches your own Kong; to watch a route of
# an existing gateway use `bin/koe connect`.
set -euo pipefail
cd "$(dirname "$0")/.."

BIND="127.0.0.1"; DEST="none"; SWAP_GB=2; INSTALL_DOCKER=1; HTTPS=0; DOMAIN=""; GUARDS=""; AUTH_USER="admin"; PASSFILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bind) BIND="$2"; shift 2;;
    --destination) DEST="$2"; shift 2;;
    --swap-gb) SWAP_GB="$2"; shift 2;;
    --https) HTTPS=1; shift;;
    --domain) DOMAIN="$2"; HTTPS=1; shift 2;;
    --user) AUTH_USER="$2"; shift 2;;
    --password-file) PASSFILE="$2"; shift 2;;
    --demo-guards) GUARDS="$2"; shift 2;;
    --no-docker-install) INSTALL_DOCKER=0; shift;;
    -h|--help) sed -n '2,22p' "$0"; exit 0;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac
done
[[ "$AUTH_USER" =~ ^[A-Za-z0-9._-]{1,40}$ ]] || { echo "--user: letters, digits, . _ - only" >&2; exit 2; }
say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
SUDO=""; [[ $EUID -eq 0 ]] || SUDO="sudo"
getenv() { grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2- || true; }
setenv() { if grep -qE "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi; }

# ---------------------------------------------------------------- 1. docker
if ! command -v docker >/dev/null 2>&1; then
  [[ $INSTALL_DOCKER -eq 1 ]] || { echo "docker missing and --no-docker-install given" >&2; exit 1; }
  say "Installing Docker Engine"
  curl -fsSL https://get.docker.com | $SUDO sh >/tmp/koe-docker-install.log 2>&1 \
    || { tail -20 /tmp/koe-docker-install.log; exit 1; }
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
[[ -n "$(getenv TRANSLATE_EVERY_S)" ]] || setenv TRANSLATE_EVERY_S 300
[[ -n "$(getenv RETENTION_HOURS)" ]] || setenv RETENTION_HOURS 6        # small demo host: keep the store small
# the bundled demo routes carry synthetic prompts only, so the dashboard may list them
[[ -n "$(getenv EXPORT_PROMPT_CHARS)" ]] || setenv EXPORT_PROMPT_CHARS 240

if [[ -n "$GUARDS" ]]; then
  say "Generating stand-in guardrails: $GUARDS"
  # shellcheck disable=SC2086
  scripts/gen-demo-guards.sh $GUARDS | head -1
  setenv DEMO_CONSOLE true
  [[ -n "$(getenv DEMO_TRAFFIC_MAX_MIN)" ]] || setenv DEMO_TRAFFIC_MAX_MIN 120
fi

CADDY=""; CADDY_VOL=""; NEW_PASSWORD=""
if [[ $HTTPS -eq 1 ]]; then
  if [[ -z "$DOMAIN" ]]; then
    IP="$(curl -fsS --max-time 5 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]')"
    [[ "$IP" =~ ^[0-9.]+$ ]] || { echo "could not find this host's public IP; pass --domain" >&2; exit 1; }
    DOMAIN="${IP//./-}.sslip.io"
  fi
  setenv EYES_DOMAIN "$DOMAIN"
  [[ -n "$(getenv CADDY_IMAGE)" ]] || setenv CADDY_IMAGE "caddy:2-alpine"
  BIND="127.0.0.1"
  # one user and password in front of everything; only the hash is kept
  PW=""
  if [[ -n "$PASSFILE" ]]; then
    [[ -s "$PASSFILE" ]] || { echo "--password-file $PASSFILE is empty or missing" >&2; exit 1; }
    PW="$(head -n1 "$PASSFILE")"; rm -f "$PASSFILE"
  elif [[ ! -s deploy/auth.caddy ]]; then
    PW="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | cut -c1-20)"; NEW_PASSWORD="$PW"
  fi
  if [[ -n "$PW" ]]; then
    HASH="$(DRUN docker run --rm -e KOE_PW="$PW" "$(getenv CADDY_IMAGE)" sh -c 'caddy hash-password --plaintext "$KOE_PW"' | tail -1)"
    [[ "$HASH" == \$2* ]] || { echo "could not hash the password" >&2; exit 1; }
    printf 'basic_auth {\n\t%s %s\n}\n' "$AUTH_USER" "$HASH" > deploy/auth.caddy
    say "Front-door login set for user $AUTH_USER"
  fi
  CADDY="  caddy:
    image: \${CADDY_IMAGE}
    restart: unless-stopped
    environment:
      EYES_DOMAIN: \${EYES_DOMAIN}
    ports: [\"80:80\", \"443:443\"]
    volumes:
      - ./deploy:/etc/caddy:ro
      - caddy-data:/data
    depends_on: [evaluator, kong]"
  CADDY_VOL="  caddy-data: {}"
  say "HTTPS on https://${DOMAIN%%,*} (certificate issued automatically by Caddy)"
fi

GRAFANA=""; GRAFANA_VOL=""
if [[ "$DEST" == "grafana" || "$DEST" == "both" ]]; then      # optional extra, reachable on this host only
  [[ -n "$(getenv GRAFANA_ADMIN_PASSWORD)" ]] || setenv GRAFANA_ADMIN_PASSWORD "$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | cut -c1-20)"
  GRAFANA="  alloy:
    ports: !override
      - \"127.0.0.1:\${ALLOY_PORT:-12345}:12345\"
      - \"127.0.0.1:\${OTLP_HTTP_PORT:-4318}:4318\"
  loki:
    ports: !override
      - \"127.0.0.1:\${LOKI_PORT:-3100}:3100\"
  prometheus:
    ports: !override
      - \"127.0.0.1:\${PROMETHEUS_PORT:-9090}:9090\"
  grafana:
    ports: !override
      - \"127.0.0.1:\${GRAFANA_PORT:-3000}:3000\"
    volumes:
      - grafana-data:/var/lib/grafana"
  GRAFANA_VOL="  grafana-data: {}"
fi

say "Writing docker-compose.override.yml (ports bound to ${BIND})"
cat > docker-compose.override.yml <<YAML
# Generated by deploy/install.sh. Delete this file to go back to the plain compose defaults.
services:
  kong:
    restart: unless-stopped
    ports: !override
      - "${BIND}:\${KONG_PROXY_PORT:-8000}:8000"
      - "127.0.0.1:\${KONG_ADMIN_PORT:-8001}:8001"
      - "127.0.0.1:\${KONG_STATUS_PORT:-8100}:8100"
  evaluator:
    restart: unless-stopped
    environment:
      DEMO_GRAFANA_URL: ""
    ports: !override
      - "${BIND}:\${EVALUATOR_PORT:-8800}:8000"
  mock-llm:
    restart: unless-stopped
${GRAFANA}
${CADDY}
volumes:
  evaluator-data: {}
${GRAFANA_VOL}
${CADDY_VOL}
YAML

# ----------------------------------------------------------------- 6. stack
say "Running scripts/setup.sh --destination ${DEST}"
DRUN scripts/setup.sh --destination "$DEST"

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
  D="${DOMAIN%%,*}"
  echo "   Dashboard   https://${D}/                 user ${AUTH_USER}"
  [[ -z "$NEW_PASSWORD" ]] || echo "   Password    ${NEW_PASSWORD}     (shown once; only its hash is stored)"
  echo "   3D chain    https://${D}/chain"
  [[ -z "$GUARDS" ]] || echo "   Console     https://${D}/demo"
  echo "   Ingest      https://${D}/ingest/kong      for: bin/koe connect --ingest-url ... (token: grep INGEST_TOKEN $(pwd)/.env)"
  echo "   Kong (demo) https://${D}/kong/ai/named"
  echo "   The first page load can take up to a minute while the certificate is issued."
else
  HOST_HINT="$(hostname -I 2>/dev/null | awk '{print $1}')"; [[ "$BIND" == "127.0.0.1" ]] && HOST_HINT="localhost"
  [[ "$BIND" != "127.0.0.1" ]] || echo "   Ports are bound to localhost. From your machine: ssh -N -L ${EVALUATOR_PORT:-8800}:localhost:${EVALUATOR_PORT:-8800} <user>@<this-host>"
  echo "   Dashboard   http://${HOST_HINT}:${EVALUATOR_PORT:-8800}/dashboard"
  echo "   3D chain    http://${HOST_HINT}:${EVALUATOR_PORT:-8800}/chain"
  echo "   Kong proxy  http://${HOST_HINT}:${KONG_PROXY_PORT:-8000}"
fi
