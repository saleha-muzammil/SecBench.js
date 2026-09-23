#!/usr/bin/env bash
# Re-run the 17 benchmarks that never produced a verdict, in parallel under tmux.
#
#   ./rerun-failed-tmux.sh            # tier 1 only (12 re-runnable as-is)
#   ./rerun-failed-tmux.sh all        # tier 1 + tier 2 (adds the detected-seed one)
#   LANES=6 ./rerun-failed-tmux.sh    # change concurrency (default 4)
#
# One tmux window per lane; each lane walks its slice sequentially. Concurrency is
# bounded by LANES, so docker builds and agent runs don't thrash the laptop.
# Every benchmark gets its OWN --out dir: the runner writes selection.json and
# summary.csv at the top of --out, so sharing one would corrupt both.
set -uo pipefail
cd "$(dirname "$0")"

SESSION=${SESSION:-rerun-failed}
LANES=${LANES:-4}
OUTROOT=${OUTROOT:-stratified-rerun-failed}

# category:folder:extra-flags   (-fixed.csv covers all 17; the default
# prototype-pollution CSV is missing lodash_4.17.9, and --only skips rows it
# cannot find in the CSV, so pin the CSV explicitly.)
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

JOBS=("${TIER1[@]}")
[ "${1:-}" = "all" ] && JOBS+=("${TIER2[@]}")

mkdir -p "$OUTROOT/logs"
tmux has-session -t "$SESSION" 2>/dev/null && { echo "session '$SESSION' exists; tmux kill-session -t $SESSION first"; exit 1; }
tmux new-session -d -s "$SESSION" -n lane0

for ((i=0;i<LANES;i++)); do
  slice=()
  for ((j=i;j<${#JOBS[@]};j+=LANES)); do slice+=("${JOBS[$j]}"); done
  [ ${#slice[@]} -eq 0 ] && continue

  script="$OUTROOT/logs/lane$i.sh"
  { echo '#!/usr/bin/env bash'
    echo 'set -uo pipefail'
    for job in "${slice[@]}"; do
      cat="${job%%:*}"; rest="${job#*:}"; folder="${rest%%:*}"; extra="${rest#*:}"
      cat <<EOF
echo "=== $cat/$folder ==="
python3 run_stratified_full_loop.py \\
  -c $cat --only $folder \\
  --csv $cat=evasion-campaign-$cat-fixed.csv \\
  --out $OUTROOT/$folder \\
  --docker-loop --no-regen $extra \\
  --max-iterations 5 --cost-limit 0.3 \\
  --extra "--no-run-codegen --gate-in-loop --gate-runs 1 --revise-iterations 2" \\
  2>&1 | tee $OUTROOT/logs/$folder.log
echo "=== $cat/$folder rc=\$? ==="
EOF
    done
    echo 'echo "LANE DONE"; exec bash'
  } > "$script"
  chmod +x "$script"

  [ $i -eq 0 ] && tmux rename-window -t "$SESSION:0" "lane0" || tmux new-window -t "$SESSION" -n "lane$i"
  tmux send-keys -t "$SESSION:lane$i" "./$script" C-m
done

tmux new-window -t "$SESSION" -n watch
tmux send-keys -t "$SESSION:watch" \
  "while :; do clear; ./rerun-failed-parallel.sh status; sleep 20; done" C-m

echo "launched $SESSION: ${#JOBS[@]} benchmarks across $LANES lanes"
echo "attach:  tmux attach -t $SESSION"
