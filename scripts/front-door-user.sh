#!/usr/bin/env bash
# Add, change or remove a person who can sign in to a public install. Run it on the host, in the install directory.
#
#   KOE_PASSWORD=... scripts/front-door-user.sh add NAME      (or type the password when asked)
#   scripts/front-door-user.sh remove NAME
#   scripts/front-door-user.sh list
#
# Only a hash of the password is kept, in .env (FRONT_DOOR_USERS). The collector is restarted to pick it up.
# The first user, set by deploy/install.sh --user, is not managed here.
set -euo pipefail
cd "$(dirname "$0")/.."
CMD="${1:-}"; NAME="${2:-}"
[[ "$CMD" =~ ^(add|remove|list)$ ]] || { sed -n '2,9p' "$0"; exit 2; }
if [[ "$CMD" != list ]]; then
  [[ "$NAME" =~ ^[A-Za-z0-9._-]{1,40}$ ]] || { echo "NAME: letters, digits, . _ - only" >&2; exit 2; }
fi
if [[ "$CMD" == add && -z "${KOE_PASSWORD:-}" ]]; then read -r -s -p "Password for $NAME: " KOE_PASSWORD; echo; fi
touch .env; chmod 600 .env
KOE_PASSWORD="${KOE_PASSWORD:-}" python3 - "$CMD" "$NAME" <<'PY'
import hashlib, os, pathlib, secrets, sys
cmd, name = sys.argv[1], sys.argv[2]
env = pathlib.Path(".env"); lines = env.read_text().splitlines()
cur = next((l.split("=", 1)[1] for l in lines if l.startswith("FRONT_DOOR_USERS=")), "")
users = dict(p.split("=", 1) for p in cur.split(";") if "=" in p)
if cmd == "list":
    first = next((l.split("=", 1)[1] for l in lines if l.startswith("FRONT_DOOR_USER=")), "")
    print("\n".join(([first + "   (first user)"] if first else []) + sorted(users)) or "nobody yet"); sys.exit(0)
if cmd == "add":
    pw = os.environ.get("KOE_PASSWORD") or sys.exit("no password given")
    salt, n = secrets.token_bytes(16), 200000
    users[name] = "pbkdf2:%d:%s:%s" % (n, salt.hex(), hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, n).hex())
else:
    users.pop(name, None)
lines = [l for l in lines if not l.startswith("FRONT_DOOR_USERS=")] + ["FRONT_DOOR_USERS=" + ";".join(f"{k}={v}" for k, v in sorted(users.items()))]
env.write_text("\n".join(lines) + "\n")
print(("added or updated " if cmd == "add" else "removed ") + name)
PY
[[ "$CMD" == list ]] || { D=(docker); docker info >/dev/null 2>&1 || D=(sudo docker); "${D[@]}" compose up -d --no-deps evaluator >/dev/null 2>&1 && echo "collector restarted"; }
