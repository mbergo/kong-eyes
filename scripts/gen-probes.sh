#!/usr/bin/env bash
# Generate the middle probe plugins for a guardrail chain.
#
#   scripts/gen-probes.sh --guardrails fixture-input-guard:775,ai-prompt-guard:771,ai-proxy:770,fixture-output-guard:760
#
# One probe is placed in every gap between neighbouring priorities (and one below the lowest), so the
# head plugin (790) and the tail plugin (5) bracket each guardrail. Open-source Kong fixes one priority
# per plugin name, hence one generated plugin per position: kong/plugins/gro-probe-<priority>/.
set -euo pipefail
cd "$(dirname "$0")/.."
HEAD=790; TAIL=5; SPEC=""; OUT="kong/plugins"; CLEAN=0
while [[ $# -gt 0 ]]; do case "$1" in
  --guardrails) SPEC="$2"; shift 2;;
  --out) OUT="$2"; shift 2;;
  --clean) CLEAN=1; shift;;
  -h|--help) sed -n 2,9p "$0"; exit 0;;
  *) echo "unknown argument: $1" >&2; exit 2;;
esac; done
[[ -n "$SPEC" ]] || { echo "need --guardrails name:priority,..." >&2; exit 2; }

mapfile -t PRIOS < <(tr ',' '\n' <<<"$SPEC" | awk -F: '{ if ($2 !~ /^[0-9]+$/) { print "bad entry: " $0 > "/dev/stderr"; exit 2 } print $2 }' | sort -rnu)
for p in "${PRIOS[@]}"; do
  (( p < HEAD )) || { echo "priority $p is not below the head plugin ($HEAD): that plugin runs before the observer and cannot be bracketed" >&2; exit 2; }
  (( p > TAIL )) || { echo "priority $p is not above the tail plugin ($TAIL)" >&2; exit 2; }
done

PROBES=(); WARN=()
for ((i=0; i<${#PRIOS[@]}; i++)); do
  hi=${PRIOS[$i]}
  if (( i + 1 < ${#PRIOS[@]} )); then lo=${PRIOS[$((i+1))]}; else lo=$(( hi - 20 > TAIL ? hi - 20 : TAIL )); fi
  if (( hi - lo >= 2 )); then PROBES+=( $(( (hi + lo) / 2 )) )
  else WARN+=( "priorities $hi and $lo are adjacent: no probe fits between them; a block there is reported with both as candidates" ); fi
done

[[ $CLEAN -eq 1 ]] && rm -rf "$OUT"/gro-probe-*
for p in "${PROBES[@]}"; do
  d="$OUT/gro-probe-$p"; mkdir -p "$d"
  for f in handler.lua schema.lua; do
    sed "s/__PRIORITY__/$p/g; s/__NAME__/gro-probe-$p/g" kong/plugins/_probe-template/$f > "$d/$f"
  done
done

names=$(printf 'gro-probe-%s,' "${PROBES[@]}"); names=${names%,}
echo "probes written: ${PROBES[*]}"
for w in "${WARN[@]:-}"; do [[ -n "$w" ]] && echo "note: $w"; done
echo
echo "KONG_PLUGINS=bundled,guardrail-observer,guardrail-observer-tail,$names"
echo
echo "route plugins (add next to guardrail-observer and guardrail-observer-tail):"
for p in "${PROBES[@]}"; do echo "          - name: gro-probe-$p"; done
