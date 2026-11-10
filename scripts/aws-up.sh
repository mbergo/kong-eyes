#!/usr/bin/env bash
# Spawn an EC2 instance with the whole kong-eyes stack and the dashboard on HTTPS.
#
#   scripts/aws-up.sh NAME [--region R] [--type t3.small] [--domain my.host.example]
#                          [--ssh-cidr 1.2.3.4/32] [--mock-minutes 60] [--dry-run]
#   scripts/aws-up.sh NAME --destroy [--region R]
#
# Uses your current AWS CLI credentials. Creates, all tagged project=kong-eyes and named after NAME:
#   - a key pair            (private key saved to ~/.ssh/kong-eyes-NAME.pem)
#   - a security group      (22 from your IP only; 80 and 443 from anywhere, needed for the certificate)
#   - one Ubuntu 24.04 instance, 30 GB gp3
# then ships this directory over SSH and runs deploy/install.sh --https on it.
#
# Without --domain the address is https://<public-ip-with-dashes>.sslip.io. The public IP changes if
# you stop and start the instance; re-run this script to re-issue for the new address.
# Re-running with the same NAME reuses the instance and updates the install. --destroy removes all three.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="${1:-}"; [[ -n "$NAME" && "$NAME" != -* ]] || { sed -n '2,16p' "$0"; exit 2; }
shift
[[ "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,40}$ ]] || { echo "NAME: letters, digits, - and _ only" >&2; exit 2; }
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null || true)}}"
TYPE="t3.small"; DOMAIN=""; SSH_CIDR=""; MOCK_MIN=60; DESTROY=0; DRY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --region) REGION="$2"; shift 2;;
    --type) TYPE="$2"; shift 2;;
    --domain) DOMAIN="$2"; shift 2;;
    --ssh-cidr) SSH_CIDR="$2"; shift 2;;
    --mock-minutes) MOCK_MIN="$2"; shift 2;;
    --destroy) DESTROY=1; shift;;
    --dry-run) DRY=1; shift;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac
done
[[ -n "$REGION" ]] || { echo "no region: pass --region or configure one" >&2; exit 2; }
command -v aws >/dev/null || { echo "aws CLI not found" >&2; exit 1; }
A() { aws --region "$REGION" --output text "$@"; }
say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

RES="kong-eyes-$NAME"; KEY="$HOME/.ssh/$RES.pem"
WHO="$(A sts get-caller-identity --query Arn)"
say "AWS identity $WHO, region $REGION"

instance_id() {
  A ec2 describe-instances --filters "Name=tag:Name,Values=$NAME" "Name=tag:project,Values=kong-eyes" \
    "Name=instance-state-name,Values=pending,running,stopping,stopped" --query 'Reservations[].Instances[].InstanceId' | awk '{print $1}'
}
sg_id() { A ec2 describe-security-groups --filters "Name=group-name,Values=$RES" --query 'SecurityGroups[0].GroupId' 2>/dev/null | grep -v None || true; }

# ------------------------------------------------------------------ destroy
if [[ $DESTROY -eq 1 ]]; then
  IID="$(instance_id)"
  if [[ -n "$IID" ]]; then
    say "Terminating $IID"; [[ $DRY -eq 1 ]] || { A ec2 terminate-instances --instance-ids "$IID" >/dev/null; A ec2 wait instance-terminated --instance-ids "$IID"; }
  fi
  SG="$(sg_id)"; if [[ -n "$SG" ]]; then say "Deleting security group $SG"; [[ $DRY -eq 1 ]] || A ec2 delete-security-group --group-id "$SG" >/dev/null; fi
  if A ec2 describe-key-pairs --key-names "$RES" >/dev/null 2>&1; then
    say "Deleting key pair $RES"; [[ $DRY -eq 1 ]] || { A ec2 delete-key-pair --key-name "$RES" >/dev/null; rm -f "$KEY"; }
  fi
  say "Gone"; exit 0
fi

# ------------------------------------------------------------------- create
IID="$(instance_id)"
if [[ -z "$IID" ]]; then
  AMI="$(A ssm get-parameter --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value)"
  [[ -n "$SSH_CIDR" ]] || SSH_CIDR="$(curl -fsS --max-time 8 https://checkip.amazonaws.com | tr -d '[:space:]')/32"
  say "Will create: key pair $RES, security group $RES (ssh from $SSH_CIDR, 80/443 open), $TYPE from $AMI named $NAME"
  [[ $DRY -eq 0 ]] || { say "dry run: nothing created"; exit 0; }

  if ! A ec2 describe-key-pairs --key-names "$RES" >/dev/null 2>&1; then
    mkdir -p "$HOME/.ssh"; (umask 077; A ec2 create-key-pair --key-name "$RES" --key-type ed25519 \
      --tag-specifications "ResourceType=key-pair,Tags=[{Key=project,Value=kong-eyes}]" --query KeyMaterial > "$KEY")
  fi
  [[ -s "$KEY" ]] || { echo "key pair $RES exists in AWS but $KEY is missing here; --destroy first or restore the file" >&2; exit 1; }

  SG="$(sg_id)"
  if [[ -z "$SG" ]]; then
    VPC="$(A ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId')"
    [[ "$VPC" == vpc-* ]] || { echo "no default VPC in $REGION" >&2; exit 1; }
    SG="$(A ec2 create-security-group --group-name "$RES" --description "kong-eyes $NAME" --vpc-id "$VPC" \
      --tag-specifications "ResourceType=security-group,Tags=[{Key=project,Value=kong-eyes},{Key=Name,Value=$NAME}]" --query GroupId)"
    A ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 22 --cidr "$SSH_CIDR" >/dev/null
    A ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 80 --cidr 0.0.0.0/0 >/dev/null
    A ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 443 --cidr 0.0.0.0/0 >/dev/null
  fi

  IID="$(A ec2 run-instances --image-id "$AMI" --instance-type "$TYPE" --key-name "$RES" --security-group-ids "$SG" \
    --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=30,VolumeType=gp3,DeleteOnTermination=true}' \
    --metadata-options 'HttpTokens=required' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=project,Value=kong-eyes}]" \
    --query 'Instances[0].InstanceId')"
  say "Launched $IID"
else
  say "Reusing instance $IID"
  [[ $DRY -eq 0 ]] || { say "dry run: would update the install on $IID"; exit 0; }
  [[ -s "$KEY" ]] || { echo "$KEY is missing; cannot SSH to the existing instance" >&2; exit 1; }
  A ec2 start-instances --instance-ids "$IID" >/dev/null 2>&1 || true
fi

A ec2 wait instance-running --instance-ids "$IID"
IP="$(A ec2 describe-instances --instance-ids "$IID" --query 'Reservations[0].Instances[0].PublicIpAddress')"
[[ "$IP" =~ ^[0-9.]+$ ]] || { echo "instance has no public IP" >&2; exit 1; }
say "Instance $IID is running at $IP; waiting for SSH"
SSH=(ssh -i "$KEY" -o IdentitiesOnly=yes -o IdentityAgent=none -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -o BatchMode=yes)
for _ in $(seq 1 40); do "${SSH[@]}" "ubuntu@$IP" 'cloud-init status --wait >/dev/null 2>&1; true' 2>/dev/null && break; sleep 5; done

EXTRA=(--https --mock-minutes "$MOCK_MIN"); [[ -z "$DOMAIN" ]] || EXTRA+=(--domain "$DOMAIN")
scripts/deploy-remote.sh "ubuntu@$IP" -i "$KEY" -- "${EXTRA[@]}"

echo
say "Done"
echo "   SSH        ssh -i $KEY -o IdentitiesOnly=yes ubuntu@$IP"
echo "   Password   ssh -i $KEY -o IdentitiesOnly=yes ubuntu@$IP 'grep GRAFANA_ADMIN_PASSWORD kong-eyes/.env'"
echo "   Tear down  scripts/aws-up.sh $NAME --destroy --region $REGION"
[[ -z "$DOMAIN" ]] || echo "   Point $DOMAIN at $IP (A record) before opening the dashboard."
