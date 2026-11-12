#!/usr/bin/env bash
# Stand up a Kong Eyes demo on Google Cloud: one small VM, HTTPS, one user and password in front.
#
#   KOE_PASSWORD=... scripts/gcp-up.sh NAME [--project P] [--zone us-east4-a] [--type e2-small] [--disk-type pd-balanced]
#                                           [--user admin] [--domain my.host.example] [--guards "onyx straiker"]
#   scripts/gcp-up.sh NAME --destroy [--project P] [--zone Z]
#
# Uses your current gcloud login. Creates, all labelled project=kong-eyes and named after NAME:
#   - a reserved external IP address   (so a DNS name you point at it keeps working)
#   - a firewall rule                  (80 and 443 from anywhere, only for instances tagged NAME)
#   - one Ubuntu 24.04 VM, 30 GB disk
# (--disk-type pd-standard avoids the regional SSD quota. OS Login is left as the project sets it; many organisations require it)
# then ships this directory over SSH and runs deploy/install.sh --https on it. SSH uses gcloud's own key and
# the project's default firewall rules; nothing else in the project is touched.
#
# The password for the front door is read from the KOE_PASSWORD environment variable (never from a flag,
# so it stays out of shell history) and only its hash is stored on the VM. Without it one is generated and
# printed once. Without --domain the address is https://<ip-with-dashes>.sslip.io; to move to your own name,
# point an A record at the IP and re-run with --domain NAME.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="${1:-}"; [[ -n "$NAME" && "$NAME" != -* ]] || { sed -n '2,19p' "$0"; exit 2; }
shift
[[ "$NAME" =~ ^[a-z][a-z0-9-]{1,40}$ ]] || { echo "NAME: lowercase letters, digits and - only" >&2; exit 2; }
PROJECT="$(gcloud config get-value project 2>/dev/null)"; ZONE="us-east4-a"; TYPE="e2-small"; AUTH_USER="admin"; DOMAIN=""; GUARDS="onyx straiker"; DESTROY=0; DISK="pd-balanced"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="$2"; shift 2;;
    --zone) ZONE="$2"; shift 2;;
    --type) TYPE="$2"; shift 2;;
    --disk-type) DISK="$2"; shift 2;;
    --user) AUTH_USER="$2"; shift 2;;
    --domain) DOMAIN="$2"; shift 2;;
    --guards) GUARDS="$2"; shift 2;;
    --destroy) DESTROY=1; shift;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac
done
[[ -n "$PROJECT" ]] || { echo "no project: pass --project or run gcloud config set project" >&2; exit 2; }
REGION="${ZONE%-*}"
G() { gcloud --project "$PROJECT" --quiet "$@"; }
say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
say "Google Cloud project $PROJECT, zone $ZONE, as $(gcloud config get-value account 2>/dev/null)"

if [[ $DESTROY -eq 1 ]]; then
  G compute instances describe "$NAME" --zone "$ZONE" >/dev/null 2>&1 && { say "Deleting VM $NAME"; G compute instances delete "$NAME" --zone "$ZONE"; }
  G compute firewall-rules describe "$NAME-web" >/dev/null 2>&1 && { say "Deleting firewall rule $NAME-web"; G compute firewall-rules delete "$NAME-web"; }
  G compute addresses describe "$NAME-ip" --region "$REGION" >/dev/null 2>&1 && { say "Releasing address $NAME-ip"; G compute addresses delete "$NAME-ip" --region "$REGION"; }
  say "Gone"; exit 0
fi

G compute addresses describe "$NAME-ip" --region "$REGION" >/dev/null 2>&1 || { say "Reserving an external IP ($NAME-ip)"; G compute addresses create "$NAME-ip" --region "$REGION" >/dev/null; }
IP="$(G compute addresses describe "$NAME-ip" --region "$REGION" --format='value(address)')"
G compute firewall-rules describe "$NAME-web" >/dev/null 2>&1 || { say "Opening 80 and 443 for instances tagged $NAME"
  G compute firewall-rules create "$NAME-web" --network default --allow tcp:80,tcp:443 --source-ranges 0.0.0.0/0 --target-tags "$NAME" \
    --description "kong-eyes demo: HTTPS front door" >/dev/null; }
if ! G compute instances describe "$NAME" --zone "$ZONE" >/dev/null 2>&1; then
  say "Creating VM $NAME ($TYPE, Ubuntu 24.04) at $IP"
  G compute instances create "$NAME" --zone "$ZONE" --machine-type "$TYPE" --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
    --boot-disk-size 30GB --boot-disk-type "$DISK" --address "$IP" --tags "$NAME" --labels project=kong-eyes \
    --shielded-secure-boot >/dev/null
else
  say "Reusing VM $NAME at $IP"
  G compute instances start "$NAME" --zone "$ZONE" >/dev/null 2>&1 || true
fi

say "Waiting for SSH"
WHO=""
for _ in $(seq 1 30); do
  WHO="$(G compute ssh "$NAME" --zone "$ZONE" --command 'cloud-init status --wait >/dev/null 2>&1; whoami' 2>/dev/null | tail -1 || true)"
  [[ -n "$WHO" ]] && break; sleep 6
done
[[ -n "$WHO" ]] || { echo "could not SSH to $NAME" >&2; exit 1; }

EXTRA=(--https --user "$AUTH_USER"); [[ -z "$GUARDS" ]] || EXTRA+=(--demo-guards "$GUARDS")
[[ -z "$DOMAIN" ]] || EXTRA+=(--domain "$DOMAIN")
PF=()
if [[ -n "${KOE_PASSWORD:-}" ]]; then
  TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT; (umask 077; printf '%s\n' "$KOE_PASSWORD" > "$TMP"); PF=(--password-file "$TMP")
fi
scripts/deploy-remote.sh "$WHO@$IP" -i "$HOME/.ssh/google_compute_engine" "${PF[@]}" -- "${EXTRA[@]}"

echo
say "Done"
echo "   Address    $IP   (reserved; point your DNS A record here, then re-run with --domain NAME)"
echo "   SSH        gcloud compute ssh $NAME --zone $ZONE --project $PROJECT"
echo "   Tear down  scripts/gcp-up.sh $NAME --destroy --project $PROJECT --zone $ZONE"
