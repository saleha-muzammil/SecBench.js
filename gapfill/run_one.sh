#!/bin/bash
# One benchmark through the full loop. Invoked by run_all.sh via xargs; also usable alone:
#   bash gapfill/run_one.sh redos marked_0.3.6
set -uo pipefail
cd "$(dirname "$0")/.."

cat="$1"; folder="$2"
OUT="${OUT:-stratified-samples-gapfill}"
SRC="${SRC:-/tmp/gapfill-src}"
COST="${COST:-0.3}"
TIMEOUT="${TIMEOUT:-14400}"
RESUME="${RESUME:-0}"

mkdir -p "$OUT/_logs"
log="$OUT/_logs/${cat}--${folder}.log"
prog="$OUT/_logs/_progress.log"

resume_flag=(); [ "$RESUME" = "1" ] && resume_flag=(--resume)

echo "[$(date +%H:%M:%S)] START $cat/$folder" >> "$prog"

# --allow-detected-seed : the synthesized seed is the plain revert, not an evading form, so the
#                         findings never say detected_by=neither. Without this every target aborts.
# --no-regen            : never let run_evasion_campaign.py overwrite the synthesized seed.
# --no-preflight        : belt-and-braces; docker-loop mode already skips the host preflight.
python3 -u run_stratified_full_loop.py \
    -c "$cat" --only "$folder" \
    --csv "$cat=gapfill/$cat.csv" \
    --allow-detected-seed \
    --no-regen \
    --no-preflight \
    --out "$OUT" --src-dir "$SRC" \
    --cost-limit "$COST" --pipeline-timeout "$TIMEOUT" \
    "${resume_flag[@]}" \
    > "$log" 2>&1
rc=$?

v=$(python3 - "$OUT/$cat/$folder/run_meta.json" "$rc" <<'PY' 2>/dev/null || echo "rc=$rc | no run_meta"
import json, sys
d = json.load(open(sys.argv[1]))
print(d.get("status", "?"), "|", (d.get("verdict") or d.get("error") or "")[:100])
PY
)
echo "[$(date +%H:%M:%S)] DONE  $cat/$folder -> $v" >> "$prog"
echo "[$(date +%H:%M:%S)] DONE  $cat/$folder -> $v"
