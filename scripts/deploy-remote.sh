#!/usr/bin/env bash
# Ship this directory to a host over SSH and run deploy/install.sh there.
#
#   scripts/deploy-remote.sh user@host [-i key.pem] [-d remote_dir] [-- install.sh args...]
#
# Example: scripts/deploy-remote.sh ubuntu@1.2.3.4 -i ~/key.pem -- --mock-minutes 30
#
# Local secrets and state are NOT shipped (.env, generated Kong config, caches); the remote
# host generates its own. Re-running updates the files and restarts what changed.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET="${1:-}"; [[ -n "$TARGET" && "$TARGET" != -* ]] || { sed -n '2,9p' "$0"; exit 2; }
shift
KEY=""; RDIR="kong-eyes"; EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -i) KEY="$2"; shift 2;;
    -d) RDIR="$2"; shift 2;;
    --) shift; EXTRA=("$@"); break;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac
done
SSH=(ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new)
# IdentitiesOnly + no agent: an SSH agent offering many keys trips "Too many authentication failures"
[[ -z "$KEY" ]] || SSH+=(-i "$KEY" -o IdentitiesOnly=yes -o IdentityAgent=none)

echo "==> Shipping to $TARGET:~/$RDIR"
tar czf - \
  --exclude=.env --exclude='.env.bak' --exclude=.git --exclude='.build/ca.crt' --exclude=./out \
  --exclude='__pycache__' --exclude='*.pyc' --exclude=.pytest_cache \
  --exclude=docker-compose.override.yml --exclude='kong.generated.yml' . \
  | "${SSH[@]}" "$TARGET" "mkdir -p '$RDIR' && tar xzf - -C '$RDIR'"

echo "==> Running deploy/install.sh on $TARGET"
"${SSH[@]}" "$TARGET" "cd '$RDIR' && bash deploy/install.sh $(printf '%q ' "${EXTRA[@]}")"
