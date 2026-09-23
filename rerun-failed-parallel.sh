#!/usr/bin/env bash
# Re-run the benchmarks that never produced a verdict, N at a time, no tmux.
#
#   ./rerun-failed-parallel.sh              # tier 1 (12 re-runnable as-is)
#   ./rerun-failed-parallel.sh all          # + dirty-json_0.4.0 (--allow-detected-seed)
#   JOBS=6 ./rerun-failed-parallel.sh       # concurrency (default 4)
#   ./rerun-failed-parallel.sh status       # progress of a run in flight
#
# Concurrency is bounded by JOBS via xargs -P. Each benchmark gets its OWN --out:
# the runner writes selection.json + summary.csv at the top of --out, so sharing
# one across parallel processes would corrupt both.
set -uo pipefail
cd "$(dirname "$0")"

JOBS=${JOBS:-4}
OUTROOT=${OUTROOT:-stratified-rerun-failed}

TIER1=(
  code-injection:is-my-json-valid_2.20.0:
  command-injection:arpping_2.0.0:
  command-injection:kill-by-port_0.0.1:
  command-injection:pdf-image_1.0.5:
  command-injection:total.js_3.4.6:
  path-traversal:glance_3.0.0:
  path-traversal:hangersteak_0.2.2:
  prototype-pollution:dot-prop_2.0.0:
  prototype-pollution:patchmerge_1.0.1:
  prototype-pollution:set-or-get_1.2.10:
  redos:is-email_1.0.0:
  redos:terminal-kit_2.1.0:
)
TIER2=( redos:dirty-json_0.4.0:--allow-detected-seed )

# ---- status mode -----------------------------------------------------------
if [ "${1:-}" = "status" ]; then
  printf "%-32s %-12s %s\n" BENCHMARK STATE LAST
  for f in "$OUTROOT"/logs/*.log; do
    [ -e "$f" ] || { echo "(no logs yet in $OUTROOT/logs)"; exit 0; }
    b=$(basename "$f" .log)
    if   grep -q "Pipeline done"  "$f"; then s=done
    elif grep -q "ABORT\|Traceback" "$f"; then s=ABORT
    else s=running; fi
    printf "%-32s %-12s %s\n" "$b" "$s" "$(tail -n1 "$f" | cut -c1-70)"
  done
  echo
  echo "done: $(grep -l 'Pipeline done' "$OUTROOT"/logs/*.log 2>/dev/null | wc -l | tr -d ' ')/$(ls -1 "$OUTROOT"/logs/*.log 2>/dev/null | wc -l | tr -d ' ')"
  exit 0
fi

# ---- launch ----------------------------------------------------------------
JOBLIST=("${TIER1[@]}")
[ "${1:-}" = "all" ] && JOBLIST+=("${TIER2[@]}")
mkdir -p "$OUTROOT/logs"

run_one() {
  job="$1"; root="$2"
  cat="${job%%:*}"; rest="${job#*:}"; folder="${rest%%:*}"; extra="${rest#*:}"
  log="$root/logs/$folder.log"
  echo "[start] $cat/$folder"
  python3 run_stratified_full_loop.py \
    -c "$cat" --only "$folder" \
    --csv "$cat=evasion-campaign-$cat-fixed.csv" \
    --out "$root/$folder" \
    --docker-loop --no-regen $extra \
    --max-iterations 5 --cost-limit 0.3 \
    --extra "--no-run-codegen --gate-in-loop --gate-runs 1 --revise-iterations 2" \
    > "$log" 2>&1
  rc=$?
  v=$(grep -o "final_gate=\[[^]]*\]" "$log" | tail -1)
  echo "[done ] $cat/$folder rc=$rc ${v:-<no verdict>}"
}
export -f run_one

printf '%s\n' "${JOBLIST[@]}" \
  | xargs -P "$JOBS" -I{} bash -c 'run_one "$@"' _ {} "$OUTROOT"

echo
echo "=== all lanes finished -- summary ==="
"$0" status
